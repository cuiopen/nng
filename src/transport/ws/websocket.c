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

// We insist that individual headers fit in 8K.
// If you need more than that, you need something we can't do.
#define WS_BUFSIZE 8192

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

// Handshakes are HTTP headers.  They consist of either
// a request or response line, followed by key-value pairs (one per line),
// followed by an empty line.  Each line is terminated with a CRLF.
// Note that a given 'name' may be repeated, in which case its value can
// simply be appeneded to the prior value, seperated by a colon.
//
// GET <path> HTTP/1.1
// Host: <host>
// Upgrade: websocket
// Connection: Upgrade
// Origin: <somewhere> (not actually used?)
// Sec-WebSocket-Key: <xxxxx>
// Sec-WebSocket-Protocol: <x>
// Sec-WebSocket-Version: 13
// <empty>
//
// From server:
//
// HTTP/1.1 101 Switching Protocols
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Accept: <xxxx>
// Sec-WebSocket-Protocol: <x>
// <empty>
//
// Reasonable limits on header size: 8K for everything.
// Even the most borked implementation should not send more than that.
// Our maximum address length is 128 bytes.  So frankly even if we max that
// out we should be under 512 bytes (well); extra fields sent by clients,
// like client identifiers, should be *small*.  Certainly under 7.5KB.
//

typedef enum {
	WS_MODE_CLIENT = 0,
	WS_MODE_SERVER = 1,
} ws_mode;

typedef enum {
	WS_NEGO_INIT                 = 0,
	WS_NEGO_SEND_REQUEST         = 1, // client side
	WS_NEGO_RECV_RESPONSE        = 2, // client side
	WS_NEGO_RECV_REQUEST         = 3, // server side
	WS_NEGO_SEND_RESPONSE        = 4, // server side
	WS_NEGO_RECV_REQUEST_HEADER  = 5, // server side
	WS_NEGO_RECV_RESPONSE_HEADER = 6,
	WS_NEGO_FINISHED             = 8,
	WS_NEGO_FAILED               = 9,
} ws_nego_state;

struct ws_ep {
	ws_mode                mode; // client or server...
	int                    closed;
	const char *           uri; // full URI path component - MUST MATCH
	struct ws_http_server *server;
};

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

// Note that as we parse headers, the rule is that if a header is already
// present, then we can append it to the existing header, separated by
// a comma.  From experience, for example, Firefox uses a Connection:
// header with two values, "keepalive", and "upgrade".
typedef struct ws_http_header {
	char *        name;
	char *        value;
	nni_list_node node;
} ws_http_header;

struct ws_pipe {
	ws_mode       mode; // client or server
	ws_nego_state nego_state;
	uint8_t *     rxhs_buf;
	uint8_t *     txhs_buf;
	size_t        rxhs_get;
	size_t        rxhs_put;
	size_t        txhs_get;
	size_t        txhs_put;

	nni_aio *user_txaio;
	nni_aio *user_rxaio;
	nni_aio *user_negaio;

	nni_aio *txaio;
	nni_aio *rxaio;
	nni_aio *negaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;

	nni_plat_tcp_pipe *tcp;

	char *   uri;
	int      status;
	nni_list http_req_headers;
	nni_list http_rep_headers;

	uint8_t ws_key[16]; // Raw key value

#if 0
	nni_tls *tls;
#endif
};

// ws_get_line just parses (tokenizes) a single line out of the
// receive buffer at a time.  Thee buffer used to store the data is subject
// to corruption on subsequent reads, so the caller needs to do something
// useful with it before calling this routine again.
static int
ws_get_get_line(ws_pipe *p, char **buf)
{
	int     i;
	uint8_t c;
	uint8_t lastc = 0;
	size_t  len;

	if (p->rxhs_get != 0) {
		len = p->rxhs_put - p->rxhs_get;
		for (i = 0; i < len; i++) {
			p->rxhs_buf[i] = p->rxhs_buf[i + p->rxhs_get];
		}
		p->rxhs_put -= p->rxhs_get;
		p->rxhs_get = 0;
	}

	for (i = 0; i < p->rxhs_put; i++) {
		c = p->rxhs_buf[i];
		if (c == '\0') {
			return (NNG_EINVAL);
		}
		if (c == '\n') {
			if (lastc != '\r') {
				return (NNG_EINVAL);
			}
			p->rxhs_buf[i - 1] = '\0';
			p->rxhs_get        = i + 2;
			*buf               = p->rxhs_buf;
			return (0);
		}
		lastc = c;
	}

	if (p->rxhs_put >= WS_BUFSIZE) {
		return (NNG_EINVAL);
	}

	if (p->user_negaio == NULL) {
		// Canceled.
		return (NNG_ECANCELED);
	}

	if (p->tcp) {
		p->negaio->a_niov           = 1;
		p->negaio->a_iov[0].iov_buf = p->rxhs_buf + p->rxhs_put;
		p->negaio->a_iov[0].io_len  = WS_BUFSIZE - p->rxs_put;
		nni_plat_tcp_recv(p->tcp, p->negaio);
	}
	return (NNG_EAGAIN);
}

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

static int
ws_pipe_fini(void *arg)
{
	ws_pipe *p = arg;
	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negaio);

	if (p->rxhs_buf != NULL) {
		nni_free(p->rxhs_buf, WS_BUFSIZE);
	}
	if (p->txhs_buf != NULL) {
		nni_free(p->txhs_buf, WS_BUFSIZE);
	}
	if (p->tcp != NULL) {
		nni_plat_pipe_fini(p->tcp);
	}
#if 0	
	if (p->tls != NULL) {
		nni_tls_fini(p->tls);
	}
#endif
	ws_free_headers(&p->http_req_headers);
	ws_free_headers(&p->http_rep_headers);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
ws_pipe_init(ws_pipe **pipep, ws_ep *ep, void *tpp)
{
	ws_pipe *p;
	int      rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	NNI_LIST_INIT(&p->http_rep_headers, ws_http_header, node);
	NNI_LIST_INIT(&p->http_req_headers, ws_http_header, node);

	if (((p->rxhs_buf = nni_alloc(WS_BUFSIZE)) == NULL) ||
	    ((p->txhs_buf = nni_alloc(WS_BUFSIZE)) == NULL)) {
		ws_pipe_fini(p);
		return (NNG_ENOMEM);
	}

	// Initialize AIOs.
	if (((rv = nni_aio_init(&p->txaio, ws_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ws_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, ws_pipe_nego_cb, p)) !0)) {
		ws_pipe_fini(p);
		return (rv);
	}

	p->mode       = ep->mode;
	p->nego_state = WS_NEGO_INIT;
	p->rcvmax     = ep->rcvmax;
	p->addr       = ep->addr;
	p->tcp        = tpp;

	*pipep = p;
	return (0);
}

static uint16_t
ws_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->peer);
}

// ws_set_header sets a header value in the list.  This overrides any
// previous value.
static int
ws_set_header(nni_list *l, char *key, char *val)
{
	ws_http_header *h;
	NNI_LIST_FOREACH (list, h) {
		if (strcmp(key, h->name) == 0) {
			char * news;
			size_t len = strlen(val) + 1;
			if ((news = nni_alloc(len)) == NULL) {
				return (NNG_ENOMEM);
			}
			snprintf(news, len, "%s", h->value, val);
			nni_free(h->value, strlen(h->value) + 1);
			h->value = news;
			return (0);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_alloc(strlen(val) + 1)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}

	nni_list_append(list, h);
	return (0);
}

// ws_add_header adds a value to an existing header, creating it if does
// not exist.  This is for headers that can take multiple values.
static int
ws_add_header(nni_list *l, char *key, char *val)
{
	ws_http_header *h;
	NNI_LIST_FOREACH (list, h) {
		if (strcmp(key, h->name) == 0) {
			char * news;
			size_t len = strlen(h->value) + strlen(val) + 3;
			if ((news = nni_alloc(len)) == NULL) {
				return (NNG_ENOMEM);
			}
			snprintf(news, len, "%s, %s", h->value, val);
			nni_free(h->value, strlen(h->value) + 1);
			h->value = news;
			return (0);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_alloc(strlen(val) + 1)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}

	nni_list_append(list, h);
	return (0);
}

char *
ws_find_header(nni_list *list, const char *key)
{
	ws_http_header *h;
	NNI_LIST_FOREACH (list, h) {
		if (strcasecmp(h->name, key) == 0) {
			return (h->value);
		}
	}
	return (NULL);
}

void
ws_free_headers(nni_list *list)
{
	ws_http_header *h;

	while ((h = nni_list_first(list)) != NULL) {
		nni_list_remove(list, h);
		if (h->name != NULL) {
			nni_strfree(h->name);
		}
		if (h->value != NULL) {
			nni_free(h->value, strlen(h->value) + 1);
		}
		NNI_FREE_STRUCT(h);
	}
}

// ws_sprintf_headers makes either an HTTP request or an HTTP response
// object. The line is either the HTTP request line, or HTTP response line.
// Each header is dumped from the list, and finally an empty line is
// emitted. Returns either -1 or 0.  The buffer is NUL terminated on
// success.
static int
ws_sprintf_headers(char *buf, size_t sz, char *line, nni_list *list)
{
	size_t          l;
	ws_http_header *h;

	if ((l = snprintf(buf, sz, "%s\r\n", line)) >= sz) {
		return (-1);
	}
	buf += l;
	sz -= l;

	NNI_LIST_FOREACH (list, h) {
		l = snprintf(buf, sz, "%s: %s\r\n", h->name, h->value);
		if (l >= sz) {
			return (-1);
		}
		buf += sz;
		sz -= l;
	}
	if ((l = snprintf(buf, sz, "\r\n") >= sz)) {
		return (-1);
	}
	return (0);
}

static int
ws_parse_header(char *line, nni_list *list)
{
	key = line;
	ws_http_header *h;

	// Find separation between key and value
	if ((val = strchr(key, ":")) == NULL) {
		return (NNG_EINVAL);
	}

	// Trim leading and trailing whitespace from header
	*val = '\0';
	val++;
	while (*val == ' ' || *val == '\t') {
		val++;
	}
	end = val + strlen(val);
	end--;
	while ((end > val) && (*end == ' ' || *end == '\t')) {
		*end = '\0';
		end--;
	}

	// Convert key to upper case
	for (i = 0; key[i]; i++) {
		key[i] = toupper(key[i]);
	}

	NNI_LIST_FOREACH (list, h) {
		if (strcmp(key, h->name) == 0) {
			char * news;
			size_t len = strlen(h->value) + strlen(val) + 3;
			if ((news = nni_alloc(len)) == NULL) {
				return (NNG_ENOMEM);
			}
			snprintf(news, len, "%s, %s", h->value, val);
			nni_free(h->value, strlen(h->value) + 1);
			h->value = news;
			return (0);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_alloc(strlen(val) + 1)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}

	nni_list_append(list, h);
	return (0);
}

static int
ws_parse_request(char *line, char **urip)
{
	char *meth;
	char *uri;
	char *vers;

	// For now we only support GET <uri> HTTP/1.1
	meth = line;
	if ((uri = strchr(meth, ' ')) == NULL) {
		return (NNG_EINVAL);
	}
	*uri = '\0';
	uri++;

	if ((vers = strchr(uri, ' ')) == NULL) {
		return (NNG_EINVAL);
	}
	*vers = '\0';
	vers++;

	if ((strcmp(vers, "HTTP/1.1") != 0) || (strcmp(meth, "GET") != 0)) {
		return (NNG_EINVAL);
	}

	*urip = uri;
	return (0);
}

static void
ws_pipe_nego(ws_pipe *p)
{
	char *line;
	int   rv;
	char *meth;
	char *path;
	char *vers;
	char *key;
	char *val;
	char *end;

loop:
	switch (p->ws_nego_state) {
	case WS_NEGO_SEND_REQUEST:
	// xxx: client sends the request
	case WS_NEGO_RECV_REQUEST:
		// server recvs the request from the client
		if ((rv = ws_get_get_line(p, &line)) != 0) {
			if (rv == NNG_EAGAIN) { // still reading
				return;
			}
			goto err;
		}

		if ((rv = ws_parse_request(p, &uri)) != 0) {
			goto err;
		}
		if ((p->uri = nni_strdup(uri)) == NULL) {
			rv = NNG_ENOMEM;
			goto err;
		}

		// Change the start, and try getting another line.
		p->nego_state = WS_NEGO_RECV_REQUEST_HEADER;
		goto loop;

	case WS_NEGO_RECV_REQUEST_HEADER:
		if ((rv = ws_get_get_line(p, &line)) != 0) {
			if (rv == NNG_EAGAIN) {
				return;
			}
			goto err;
		}
		if (strlen(line) == 0) { // End of headers (empty line).
			ws_handle_request(p);
			return;
		}
		if ((rv = ws_parse_header(line, &p->http_req_headers)) != 0) {
			goto err;
		}
		goto loop;

	case WS_NEGO_SEND_RESPONSE:
	// XXX:

	case WS_NEGO_RECV_RESPONSE:
		// client recvs the response from the server
		if ((rv = ws_get_get_line(p, &line)) != 0) {
			if (rv == NNG_EAGAIN) { // still reading
				return;
			}
			goto err;
		}

		if ((rv = ws_parse_response(p, &p->status)) != 0) {
			goto err;
		}

		// Change the start, and try getting another line.
		p->nego_state = WS_NEGO_RECV_RESPONSE_HEADER;
		goto loop;

	case WS_NEGO_RECV_RESPONSE_HEADER:
		if ((rv = ws_get_line(p, &line)) != 0) {
			if (rv == NNG_EAGAIN) {
				return;
			}
			goto err;
		}
		if (strlen(line) == 0) {
			ws_handle_response(p);
			return;
		}
		if ((rv = ws_parse_header(line, &p->http_rep_headers)) != 0) {
			goto err;
		}
		goto loop;
	}

err:
	if ((aio = p->user_negaio != NULL)) {
		p->user_negaio = NULL;
		nni_aio_finish_error(aio, rv);
	}
}

static void
ws_negaio_cb(void *arg)
{
	ws_pipe *p   = arg;
	nni_aio *aio = p->negaio;
	size_t   n;

	nni_mtx_lock(&p->mtx);
	if (nni_aio_result(aio) != 0) {
		if ((aio = p->user_negaio) != NULL) {
			p->user_negaio = NULL;
			nni_mtx_unlock(&p->mtx);
			nni_aio_finish_error(aio, rv);
			return;
		}
	}

	n = nni_aio_count(aio);

	switch (p->nego_state) {
	case WS_NEGO_RECV_REQUEST:
	case WS_NEGO_RECV_REQUEST_HEADER:
	case WS_NEGO_RECV_RESPONSE:
	case WS_NEGO_RECV_RESPONSE_HEADER:
		// These are receive states.
		p->rxhs_put += n;
		NNI_ASSERT(p->rxhs_put <= WS_BUFSIZE);
		ws_pipe_nego(p);
		break;
	case WS_NEGO_SEND_REQUEST:
	case WS_NEGO_SEND_RESPONSE:
		p->txhs_get += n;
		NNI_ASSERT(p->txhs_get <= p->txhs_put);
		ws_pipe_nego(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_start_client(ws_pipe *p, nni_aio *aio)
{
	int       rv;
	nni_list *hdrs = &p->http_req_headers;
	char      wskey[25];
	char *    uri;
	char *    host;
	char *    line;

	if (nni_aio_start(aio, ws_cancel_nego, p) != 0) {
		return;
	}

	// Set up our random key.
	for (int i = 0; i < 4; i++) {
		uint32_t r        = nni_random();
		p->key[i * 4 + 0] = r & 0xff;
		r >>= 4;
		p->key[i * 4 + 1] = r & 0xff;
		r >>= 4;
		p->key[i * 4 + 2] = r & 0xff;
		r >>= 4;
		p->key[i * 4 + 3] = r & 0xff;
	}
	nni_base64_encode(p->key, 16, wskey, sizeof(wskey));
	wskey[24] = '\0';

	// Construct the request headers.
	//	snprintf(p->txhs_buf, "GET %s HTTP/1.1\r\nHost: %s\r\n", uri,
	// host)
	p->user_negaio = aio;
	NNI_ASSERT(p->nego_state == WS_NEGO_INIT);
	if (((rv = ws_set_header(hdrs, "Host", host)) != 0) ||
	    ((rv = ws_set_header(hdrs, "Connection", "Upgrade")) != 0) ||
	    ((rv = ws_set_header(hdrs, "Upgrade", "websocket")) != 0) ||
	    ((rv = ws_set_header(hdrs, "Sec-WebSocket-Key", wskey)) != 0) ||
	    ((rv = ws_set_header(hdrs, "Sec-WebSocket-Protocol", pro)) != 0) ||
	    ((rv = ws_set_header(hdrs, "Sec-WebSocket-Version", "13")) != 0)) {
		    p->user_negaio = NULL);
		    nni_aio_finish_error(aio, rv);
		    return;
	}
	// XXX: Origin?

	host = p->hst;
	len  = snprintf(NULL, 0, "GET %s HTTP/1.1", p->uri);
	if ((line = nni_alloc(len)) = NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}
	if (ws_sprintf_headers(p->txhs_buf, WS_BUFSIZE, line, hdrs) < 0) {
		nni_free(line, len);
		nni_aio_finish_error(aio, NNG_EINVAL);
		return;
	}

	nni_free(line, len);
	p->txhs_get   = 0;
	p->txhs_put   = strlen(p->txhs_buf);
	p->nego_state = WS_NEGO_SEND_REQUEST;

	ws_pipe_nego(p);
}

static void
ws_pipe_start_server(ws_pipe *p, nni_aio *aio)
{
	// Server side:
	// 1. Collect a complete client request.
	// 2. Parse it - client should ask for our protocol.
	// 3. Send a server reply - we send our own protocol.
	// 4. Completed!
	if (nni_aio_start(aio, ws_cancel_nego, p) != 0) {
		return;
	}

	p->user_negaio = aio;
	NNI_ASSERT(p->nego_state == WS_NEGO_INIT);
	p->nego_state = WS_NEGO_RECV_REQUEST;

	ws_pipe_nego(p);
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

	nni_mtx_lock(&p->mtx);
	switch (p->mode) {
	case WS_MODE_CLIENT:
		ws_pipe_start_client(p, aio);
		break;
	case WS_MODE_SERVER:
		ws_pipe_start_server(p, aio);
		break;
	default:
		nni_aio_finish_error(aio, NNG_EINVAL);
		break;
	}
	nni_mtx_unlock(&p->mtx);
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
