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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/base64/base64.h"
#include "supplemental/http/http.h"
#include "supplemental/sha1/sha1.h"
#include "supplemental/websocket/websocket.h"

typedef struct ws_ep   ws_ep;
typedef struct ws_pipe ws_pipe;

struct ws_ep {
	int              mode; // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
	char             addr[NNG_MAXADDRLEN + 1];
	uint16_t         lproto; // local protocol
	uint16_t         rproto; // remote protocol
	size_t           rcvmax;
	char *           host;
	char *           serv;
	char *           path;
	nni_http_client *client; // only one of client or server is valid
	nni_http_server *server;
	nni_http_handler handler; // server only
	char             protoname[64];
	nni_list         ready;
	nni_list         active;
	nni_list         aios;
	nni_mtx          mtx;
	nni_aio *        connaio;
};

// The most we will send in a single fragment.  We leave this pretty large,
// because if it is small the receiver will wind up having to reallocate
// messages a lot, and that is expensive.  If the value is *too* large,
// then the latency on handling control frames may become rather large.
// (Browsers and servers that send PING requests may become unhappy if it
// takes too long for them to get a PONG reply.)
#define WS_FRAGMENT_SIZE (1U << 20)

// WS_FRAGMENT_PREALLOC is used to indicate that we should preallocate
// data in this chunk size, when receiving a fragmented frame.  (Meaning,
// we will allocate this much extra at a time).  Large values can impact
// memory consumption negatively.  Small values will cause extra data copying
// and reallocations.  We only do this large preallocation once.  (So
// sending very large fragmented frames with websocket is going to have
// pretty poor performance.  This is a deficiency in the SP over websocket
// protocol -- we really would like to have the actual message size supplied.)
#define WS_FRAGMENT_PREALLOC (1U << 20)

#define WS_KEY_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_KEY_GUIDLEN 36

// A substantial drawback is that we never know the actual overall message
// size.  We should fix this in a follow up to the RFC.

// Websocket binary message header structure:
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

typedef enum ws_opcode {
	WS_CONT   = 0x00,
	WS_TEXT   = 0x01,
	WS_BINARY = 0x02,
	WS_CLOSE  = 0x08,
	WS_PING   = 0x09,
	WS_PONG   = 0x0A,
	WS_FINAL  = 0x80,
} ws_opcode;

typedef enum ws_rxstate {
	WS_RX_HEADER,
	WS_RX_CONTROL,
	WS_RX_PAYLOAD,
	WS_RX_CLOSE,
} ws_rxstate;

typedef enum ws_txstate {
	WS_TX_IDLE,
	WS_TX_DATA,
	WS_TX_CONTROL,
	WS_TX_CLOSE,
} ws_txstate;

// These are close reasons -- only the ones that can be sent over the
// wire are listed here.  RFC6455 reserves 1004, 1005, 1006, and 1015.
typedef enum ws_reason {
	WS_CLOSE_NORMAL_CLOSE  = 1000,
	WS_CLOSE_GOING_AWAY    = 1001,
	WS_CLOSE_PROTOCOL_ERR  = 1002,
	WS_CLOSE_UNSUPP_FORMAT = 1003,
	WS_CLOSE_INVALID_DATA  = 1007,
	WS_CLOSE_POLICY        = 1008,
	WS_CLOSE_TOO_BIG       = 1009,
	WS_CLOSE_NO_EXTENSION  = 1010,
	WS_CLOSE_INTERNAL      = 1011,
} ws_reason;

struct ws_pipe {
	int           mode; // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
	nni_list_node node;
	ws_ep *       ep;
	nni_mtx       mtx;
	nni_http *    http; // http transport

	size_t rcvmax; // inherited from EP

	bool     closed;
	uint16_t rproto;
	uint16_t lproto;

	nni_aio *user_txaio;
	nni_aio *user_rxaio;

	nni_aio *txaio;
	nni_aio *rxaio;

	nni_http_req *req;
	nni_http_res *res;

	nni_ws *ws;
};

static void
ws_pipe_send_cb(void *arg)
{
	ws_pipe *p = arg;
	nni_aio *taio;
	nni_aio *uaio;

	nni_mtx_lock(&p->mtx);
	uaio          = p->user_txaio;
	p->user_txaio = NULL;

	if (uaio != NULL) {
		int rv;
		if ((rv = nni_aio_result(taio)) != 0) {
			nni_aio_finish_error(uaio, rv);
		} else {
			nni_aio_finish(uaio, 0, 0);
		}
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_recv_cb(void *arg)
{
	ws_pipe *p = arg;
	nni_aio *uaio;
	nni_aio *raio;
	int      rv;

	nni_mtx_lock(&p->mtx);
	uaio          = p->user_rxaio;
	p->user_rxaio = NULL;
	if ((rv = nni_aio_result(raio)) != 0) {
		if (uaio != NULL) {
			nni_aio_finish_error(uaio, rv);
		}
	} else {
		nni_msg *msg = nni_aio_get_msg(raio);
		if (uaio != NULL) {
			nni_aio_finish_msg(uaio, msg);
		} else {
			nni_msg_free(msg);
		}
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_recv_cancel(nni_aio *aio, int rv)
{
	ws_pipe *p = aio->a_prov_data;
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_cancel(p->rxaio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (nni_aio_start(aio, ws_pipe_recv_cancel, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = aio;

	nni_ws_recv_msg(p->ws, p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send_cancel(nni_aio *aio, int rv)
{
	ws_pipe *p = aio->a_prov_data;
	nni_mtx_lock(&p->mtx);
	if (p->user_txaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// This aborts the upper send, which will call back with an error
	// when it is done.
	nni_aio_cancel(p->txaio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (nni_aio_start(aio, ws_pipe_send_cancel, p) != 0) {
		nni_mtx_unlock(&p->mtx);
	}
	p->user_txaio = aio;
	nni_aio_set_msg(p->txaio, nni_aio_get_msg(aio));
	nni_aio_set_msg(aio, NULL);

	nni_ws_send_msg(p->ws, p->txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);

	if (p->http) {
		nni_http_fini(p->http);
	}

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);

	if (p->req) {
		nni_http_req_fini(p->req);
	}
	if (p->res) {
		nni_http_res_fini(p->res);
	}
	if (p->ws) {
		nni_ws_fini(p->ws);
	}
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static void
ws_pipe_close(void *arg)
{
	ws_pipe *p = arg;
	// XXX: We have to do stuff here.
	// Send the close frame if not already done, for one.
	nni_mtx_lock(&p->mtx);
	if (p->closed) {
		nni_mtx_unlock(&p->mtx);
	}
	p->closed = true;

	// XXX: send a close frame.
	nni_mtx_unlock(&p->mtx);
}

static int
ws_pipe_init(ws_pipe **pipep, ws_ep *ep, void *http)
{
	ws_pipe *p;
	int      rv;
	nni_aio *aio;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	// Initialize AIOs.
	// The closeaio has no callback, but we do "wait" for it in the
	// finish handler -- it has a strict timeout to ensure that we
	// get the message out if at all possible.
	if (((rv = nni_aio_init(&p->txaio, ws_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ws_pipe_recv_cb, p)) != 0)) {
		ws_pipe_fini(p);
		return (rv);
	}

	p->mode   = ep->mode;
	p->rcvmax = ep->rcvmax;
	//	p->addr   = ep->addr;
	p->http   = http;
	p->rproto = ep->rproto;
	p->lproto = ep->lproto;

	nni_mtx_lock(&ep->mtx);
	p->ep = ep;
	if ((aio = nni_list_first(&ep->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_list_append(&ep->active, p);
		nni_aio_finish_pipe(aio, p);
	} else {
		// Leave this on the pending list.  Probably we should set
		// up a read to notice if the other side goes away, but
		// the reality is that the protocol code will do so anyway.
		nni_list_append(&ep->ready, p);
	}
	nni_mtx_unlock(&ep->mtx);

	*pipep = p;
	return (0);
}

static uint16_t
ws_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->rproto);
}

static void
ws_pipe_start(void *arg, nni_aio *aio)
{
	nni_aio_finish(aio, 0, 0);
}

// We have very different approaches for server and client.
// Servers use the HTTP server framework, and a request methodology.

static int
ws_ep_bind(void *arg)
{
	// Register with a server, and start the server running.
	// nni_http_server_add_handler(s, &ep->handler, ep);
	//	nni_http_server_start(s);
	return (0);
}

static void
ws_ep_cancel(nni_aio *aio, int rv)
{
	ws_ep *ep = aio->a_prov_data;

	nni_mtx_lock(&ep->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ws_ep_accept(void *arg, nni_aio *aio)
{
	ws_ep *  ep = arg;
	ws_pipe *p;

	// We already bound, so we just need to look for an available
	// pipe (created by the handler), and match it.
	// Otherwise we stick the AIO in the accept list.
	nni_mtx_lock(&ep->mtx);
	if (!nni_aio_start(aio, ws_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if ((p = nni_list_first(&ep->ready)) != NULL) {
		nni_list_remove(&ep->ready, p);
		nni_list_append(&ep->active, p);
		nni_aio_finish_pipe(aio, p);
	} else {
		nni_list_append(&ep->aios, aio);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ws_ep_connect(void *arg, nni_aio *aio)
{
	ws_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(nni_list_empty(&ep->aios));

	// If we can't start, then its dying and we can't report
	// either.
	if ((rv = nni_aio_start(aio, ws_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	nni_list_append(&ep->aios, aio);
	nni_http_client_connect(ep->client, ep->connaio);
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

static void
ws_ep_fini(void *arg)
{
	ws_ep *ep = arg;

	if (ep->connaio) {
		nni_aio_stop(ep->connaio);
		nni_aio_fini(ep->connaio);
	}
	nni_strfree(ep->path);
	nni_strfree(ep->host);
	nni_strfree(ep->serv);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
ws_ep_conn_cb(void *arg)
{
	ws_ep *   ep = arg;
	ws_pipe * p;
	nni_aio * aio = ep->connaio;
	nni_aio * uaio;
	nni_http *http = NULL;
	int       rv;

	nni_mtx_lock(&ep->mtx);
	if (nni_aio_result(aio) == 0) {
		http = nni_aio_get_output(aio, 0);
	}
	if ((uaio = nni_list_first(&ep->aios)) == NULL) {
		// The client stopped caring about this!
		if (http != NULL) {
			nni_http_fini(http);
		}
		return;
	}
	nni_aio_list_remove(uaio);
	if ((rv = nni_aio_result(aio)) != 0) {
		nni_aio_finish_error(uaio, rv);
	} else if ((rv = ws_pipe_init(&p, ep, http)) != 0) {
		nni_http_fini(http);
		nni_aio_finish_error(uaio, rv);
	} else {
		nni_aio_finish_pipe(uaio, p);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ws_ep_close(void *arg)
{
	ws_ep *ep;

	// We need to remove ourself from the http servers list.
	if (ep->mode == NNI_EP_MODE_LISTEN) {
		// XXX: delete handler
	} else {
		nni_aio_cancel(ep->connaio, NNG_ECLOSED);
		// XXX: Close the client?
	}
}

static int
ws_ep_init(void **epp, const char *url, nni_sock *sock, int mode)
{
	ws_ep *      ep;
	char         buf[NNG_MAXADDRLEN + 1];
	char *       path;
	char *       pair;
	char *       qparams;
	bool         https = false;
	nni_aio *    aio;
	nng_sockaddr sa;
	int          rv;

	if (nni_strlcpy(buf, url, sizeof(buf)) >= sizeof(buf)) {
		return (NNG_EADDRINVAL);
	}

	if (strncmp(buf, "ws://", strlen("ws://"))) {
		https = false;
		pair  = buf + strlen("ws://");
	} else if (strncmp(buf, "wss://", strlen("wss://"))) {
		https = true;
		pair  = buf + strlen("wss://");
		return (NNG_ENOTSUP); // NO TLS support yet.
	} else {
		return (NNG_EADDRINVAL);
	}

	if ((path = strchr(pair, '/')) != NULL) {
		*path = '\0';
		path++;
	} else {
		path = "/";
	}
	if ((qparams = strchr(path, '?')) != NULL) {
		// We do not support query parameters.  (A peer client
		// can still send them, we just will ignore them.)
		*qparams = '\0';
	}

	// Empty path is /
	if (path[0] == '\0') {
		path = "/";
	}

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&ep->mtx);

	// List of pipes (server only).
	NNI_LIST_INIT(&ep->ready, ws_pipe, node);
	NNI_LIST_INIT(&ep->active, ws_pipe, node);
	nni_aio_list_init(&ep->aios);

	ep->mode   = mode;
	ep->lproto = nni_sock_proto(sock);
	ep->rproto = nni_sock_peer(sock);

	nni_strlcpy(ep->addr, url, sizeof(ep->addr));
	if ((ep->path = nni_strdup(path)) == NULL) {
		// Full path, may include Query Parameters.
		ws_ep_fini(ep);
		return (NNG_ENOMEM);
	}

	if ((rv = nni_tran_parse_host_port(pair, &ep->host, &ep->serv)) != 0) {
		ws_ep_fini(ep);
		return (rv);
	}
	if (ep->serv == NULL) {
		if ((ep->serv = nni_strdup(https ? "443" : "80")) == NULL) {
			ws_ep_fini(ep);
			return (NNG_ENOMEM);
		}
	}

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		ws_ep_fini(ep);
		return (rv);
	}
	aio->a_addr = &sa;
	nni_plat_tcp_resolv(ep->host, ep->serv, NNG_AF_UNSPEC,
	    mode == NNI_EP_MODE_DIAL ? false : true, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);
	if (rv != 0) {
		return (rv);
	}

	if (mode == NNI_EP_MODE_DIAL) {
		(void) snprintf(ep->protoname, sizeof(ep->protoname),
		    "%s.sp.nanomsg.org", nni_sock_peer_name(sock));
		rv = nni_http_client_init(&ep->client, &sa);
		if (rv == 0) {
			rv = nni_aio_init(&ep->connaio, ws_ep_conn_cb, ep);
		}
	} else {
		(void) snprintf(ep->protoname, sizeof(ep->protoname),
		    "%s.sp.nanomsg.org", nni_sock_proto_name(sock));
		// We actually don't support query parameters, so nuke
		// them. (This is only for registration.  The client
		// can still supply them, and we will match and pass to
		// the handler.)
		rv = nni_http_server_init(&ep->server, &sa);
	}

	if (rv != 0) {
		ws_ep_fini(ep);
		return (rv);
	}
	*epp = ep;
	return (0);
}

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
	.tran_init    = NULL,
	.tran_fini    = NULL,
};

int
nng_ws_register(void)
{
	return (nni_tran_register(&ws_tran));
}
