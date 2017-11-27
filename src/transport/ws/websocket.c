//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>

#include "core/nng_impl.h"

typedef struct ws_listener ws_listener;

struct ws_listener {
	nni_mtx      lk;
	nni_list     eps;
	uint16_t     port;
	nng_sockaddr sa; // listen address.

	// XXX: nni_tls_config for the TLS configuration

	// *can be plat_tcp_ep,
	nni_plat_tcp_ep *tcp_listener;
	nni_list_node    node;
};

static nni_mtx  ws_lock;
static nni_list ws_listeners;

// Handshakes are HTTP headers.  The smallest viable header is
// a:b\n (plus one more for the trailing \n.).  So we can read up
// to 4 bytes at a time...  but we can be clever and store a bit more
// than that:
//
// GET <path> HTTP/1.1\n
// Host: <host>
// Upgrade: websocket
// Connection: Upgrade\n
// Origin: <somewhere> (not actually used?)
// Sec-WebSocket-Key: <xxxxx>
// Sec-WebSocket-Protocol: <x>
// Sec-WebSocket-Version: 13
// \n
//
// From server:
//
// HTTP/1.1 101 Switching Protocols
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Accept: <xxxx>
// Sec-WebSocket-Protocol: <x>
//
// Reasonable limits on header size: 8K for everything.
// Even the most borked implementation should not send more than that.
// Our maximum address length is 128 bytes.  So frankly even if we max that
// out we should be under 512 bytes (well); extra fields sent by clients,
// like client identifiers, should be *small*.  Certainly under 7.5KB.
//
struct ws_ep {
	int                    mode; // client or server...
	int                    closed;
	const char *           uri; // full URI path component - MUST MATCH
	struct ws_http_server *server;
};

// header structure:
//
// {
//      int fin:1;
//      int rsv:3;  -- must be zero
//      int opcode:4;
//      int mask:1;
//      int payload_len:7;
//      int extended_payload_len:16...64;
//        ... extended is 16bits if payload_len == 126
//        ... extended is 64bits if payload_len == 127
//        ... extended is absent otherwise (len <= 125)
//      int masking_key:32; (if mask == 1)
// }
//
// If the variable length of that header makes you want to vomit,
// rest assured that you are not alone.  So we will read the 16
// bits of the mandatory header parts, then use that to decide
// how many more bits to read -- between 0 and 96.
//
// client sends data with mask, server sends without
//
// opcodes:
// 0x0: continuation
// 0x1: text frame
// 0x2: binary frame
// 0x8: close
// 0x9: ping
// 0xa: pong
struct ws_pipe {
	int      mode; // client or server
	uint8_t *rxhs_buf;
	uint8_t *txhs_buf;
	size_t   rxhs_get;
	size_t   rxhs_put;
	size_t   txhs_get;
	size_t   txhs_put;

	nni_aio *user_txaio;
	nni_aio *user_rxaio;
	nni_aio *user_negaio;

	uint8_t txhead[14]; // worst case
	uint8_t rxhead[14]; // worst case
	size_t  gottxhead;
	size_t  gotrxhead;
	size_t  wanttxhead;
	size_t  wantrxhead;

	nni_aio *txaio;
	nni_aio *rxaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;
};

static int
ws_got_headers(ws_pipe *p)
{
	size_t i = 0;
	while (i <= p->rxhs_put - 2) {
		if (p->rxhs_buf[i] != '\n') {
			i++;
			continue;
		}
		if (p->rxhs_buf[i + 1] != '\n') {
			i += 2;
			continue;
		}
		return (i + 2); // so we point at just past the headers
	}
	return (0);
}

static int
ws_parse_client_request(ws_pipe *p, const char **path)
{
	int  cnt = (p->rxhs_put - p->rxhs_get);
	char c;

	if (!strncmp((char *) &p->rxhs_buf[p->rxhs_get], "GET ", 4)) {
		return (-1);
	}
	p->rxhs_get += 4;
	*path = (char *) &p->rxhs_buf[p->rxhs_get];
	if (p->rxhs_buf[p->rxhs_get] == ' ') {
		// Missing path
		return (-1);
	}
	for (;;) {
		if (p->rxhs_get >= p->rxhs_put) {
			return (-1);
		}
		switch ((c = p->rxhs_buf[p->rxhs_get])) {
		case ' ':
			if (strncmp((char *) &p->rxhsbuf[p->rxhs_get],
			        " HTTP/1.1\n", strlen(" HTTP/1.1\n")) != 0) {
				return (-1);
			}
			p->rxhs_buf[p->rxhs_get] = '\0';
			p->rxhs_get += strlen(" HTTP/1.1\n");
			return (0);
		case '\n':
			// Premature end of line
			return (-1);
		default:
			// Possibly other constraints on URI here?
			p->rxhs_get++;
		}
	}
}

static int
ws_next_header(ws_pipe *p, char **name, char **value)
{
	bool got_name;
	bool got_value;

	while (p->rxhs_get < p->rxhs_put) {
		c = p->rxhs_buf[p->rxhs_get];
		if (c == ' ') {
		}
	}
}

static void
ws_pipe_recv(void *arg, nni_aio *aio)
{
	// For receive, we want to read the mandatory header (16 bits),
	// and then we will schedule a follow up read of the residual
	// part.  However, we want to consume from the residual part
	// that might be left over from the HTTP header read.
	// Outstanding question here: do we just start a forever read,
	// loading the HTTP data, and consuming from it (following the TLS
	// model) or do we issue partial reads.  I suspect that buffering
	// here is preferable, but need to be aware of double buffering done
	// by underlying TLS.
}

static uint16_t
ws_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->peer);
}

static void
ws_pipe_start(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	// client:
	//   send our request...
	//   wait for reply...
	//
	// server:
	//   wait for client request
	//   send reply
	//
}

static void
ws_ep_cancel(nni_aio *aio, int rv)
{
	// If this is a client, we just cancel the outgoing connect
	// request.  If its an accept operation then we can simply
	// unregister from the listener.  As another issue, we may
	// have to free / close the listener if we were the final endpoint
	// there.
}

static int
ws_ep_bind(void *arg)
{
	// This will look for a listener, and start it if not already started.
	// It adds the listener to it.
}

static void
ws_ep_accept(void *arg, nni_aio *aio)
{
	// XXX: endpoint accept.  For this we need to start a listener
	// if one isn't already running.  The listener needs to handle
	// TCP completions by starting up the header negotiation, to
	// determine the actual endpoint.
	// This implies we need a list of endpoint listeners.
	// I'm not sure what to do about, or whether to support at all,
	// the notion of endpoint listeners that only listen on a specific
	// IP address instead of INADDR_ANY.  Probably we want to have
	// the bind address as the lookup key, and to treat INADDR_ANY
	// separately.  Presumably we wil fail to bind() if a conflicting
	// port reservation exists?
}

static void
ws_ep_connect(void *arg, nni_aio *aio)
{
	ws_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	// If we can't start, then its dying and we can't report either.
	if ((rv = nni_aio_start(aio, ws_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	// Start the connection process...
	// XXX: probably we should have the callback for this start the
	// endpoint negotiation.  Endpoint negotiation is a PITA.
	nni_plat_tcp_ep_connect(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ws_ep_setopt_recvmaxsz(void *arg, const void *v, size_t sz)
{
	ws_ep *ep = arg;
	if (ep == NULL) {
		return (nni_chkopt_size(v, sz, 0, NNI_MAXSZ));
	}
	return (nni_setopt_size(&ep->rcvmax, v, sz, 0, NNI_MAXSZ));
}

static int
ws_ep_getopt_recvmaxsz(void *arg, void *v, size_t *szp)
{
	ws_ep *ep = arg;
	return (nni_getopt_size(ep->rcvmax, v, szp));
}

static int
ws_tran_init(void)
{
	nni_mtx_init(&ws_lock);
	NNI_LIST_INIT(&ws_listeners, ws_listener, node);
}

static void
ws_tran_fini(void)
{
	nni_mtx_fini(&ws_lock);
}

static nni_tran_pipe_option ws_pipe_options[] = {
#if 0
	// clang-format off
	{ NNG_OPT_LOCADDR, ws_pipe_getopt_locaddr },
	{ NNG_OPT_REMADDR, ws_pipe_getopt_remaddr },
	// clang-format on
#endif
	// terminate list
	{ NULL, NULL }
};

static nni_tran_pipe ws_pipe_ops = {
	.p_fini    = ws_pipe_fini,
	.p_start   = ws_pipe_start,
	.p_send    = ws_pipe_send,
	.p_recv    = ws_pipe_recv,
	.p_close   = ws_pipe_close,
	.p_peer    = ws_pipe_peer,
	.p_options = ws_pipe_options,
};

static nni_tran_ep_option ws_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_getopt = ws_ep_getopt_recvmaxsz,
	    .eo_setopt = ws_ep_setopt_recvmaxsz,
	},
#if 0
	{
	    .eo_name   = NNG_OPT_LINGER,
	    .eo_getopt = ws_ep_getopt_linger,
	    .eo_setopt = ws_ep_setopt_linger,
	},
#endif
	// terminate list
	{ NULL, NULL, NULL },
};

static nni_tran_ep ws_ep_ops = {
	.ep_init    = ws_ep_init,
	.ep_fini    = ws_ep_fini,
	.ep_connect = ws_ep_connect,
	.ep_bind    = ws_ep_bind,
	.ep_accept  = ws_ep_accept,
	.ep_close   = ws_ep_close,
	.ep_options = ws_ep_options,
};

static nni_tran ws_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "ws",
	.tran_ep      = &ws_ep_ops,
	.tran_pipe    = &ws_pipe_ops,
	.tran_init    = ws_tran_init,
	.tran_fini    = ws_tran_fini,
};

int
nng_ws_register(void)
{
	return (nni_tran_register(&ws_tran));
}
