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
#include "http.h"

// We insist that individual headers fit in 8K.
// If you need more than that, you need something we can't do.
#define HTTP_BUFSIZE 8192

// GET <path> HTTP/1.1
// Host: <host> ...
// <empty>
//
// From server:
//
// HTTP/1.1 101 Switching Protocols
// Sec-WebSocket-Protocol: <x> ...
// <empty>

// Note that as we parse headers, the rule is that if a header is already
// present, then we can append it to the existing header, separated by
// a comma.  From experience, for example, Firefox uses a Connection:
// header with two values, "keepalive", and "upgrade".
typedef struct http_header {
	char *        name;
	char *        value;
	nni_list_node node;
} http_header;

typedef enum { HTTP_MSG_REQUEST, HTTP_MSG_RESPONSE } http_msgtype;

struct nni_http_msg {
	http_msgtype type;
	int          code;
	const char * meth;
	const char * vers;
	const char * uri;
	const char * rsn;
	nni_list     hdrs;
	void *       buf;
	size_t       bufsz;
	void *       data;
	size_t       datasz;
	bool         freedata; // if true free data when the message is freed
};

typedef enum {
	HTTP_MODE_NONE   = 0,
	HTTP_MODE_CLIENT = 1,
	HTTP_MODE_SERVER = 2,
} http_conn_mode;

typedef enum {
	HTTP_READ_NONE     = 0,
	HTTP_READ_REQ_LINE = 1,
	HTTP_READ_REQ_HDRS = 2,
	HTTP_READ_REQ_DATA = 3,
	HTTP_READ_RES_LINE = 4,
	HTTP_READ_RES_HDRS = 5,
	HTTP_READ_RES_DATA = 6,
} http_read_state;

struct nni_http_conn {
	void *sock;
	void (*rd)(void *, nni_aio *);
	void (*wr)(void *, nni_aio *);
	void (*close)(void *);

	nni_list rdq; // high level http read requests
	nni_list wrq; // high level http write requests

	nni_aio *user_rd_aio;

	nni_aio *rd_aio; // bottom half read operations
	nni_aio *wr_aio; // bottom half write operations

	nni_http_req *req;
	nni_http_res *res;

	nni_mtx         mtx;
	http_conn_mode  mode;
	http_read_state read_state;

	void * rd_buf;
	size_t rd_get;
	size_t rd_put;
	size_t rd_bufsz;

	void * wr_buf;
	size_t wr_get;
	size_t wr_put;
};

int
nni_http_msg_del_header(nni_http_msg *msg, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (&msg->hdrs, h) {
		if (strcasecmp(key, h->name) == 0) {
			nni_list_remove(h);
			nni_strfree(h->name);
			nni_free(h->value, strlen(h->value) + 1);
			NNI_FREE_STRUCT(h);
			return (0);
		}
	}
	return (NNG_ENOENT);
}

static int
http_msg_set_header(nni_http_msg *msg, const char *key, const char *val)
{
	http_header *h;
	NNI_LIST_FOREACH (&msg->hdrs, h) {
		if (strcasecmp(key, h->name) == 0) {
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

	nni_list_append(&msg->hdrs, h);
	return (0);
}

// nni_http_msg_add_header adds a value to an existing header, creating it if
// does not exist.  This is for headers that can take multiple values.
int
nni_http_msg_add_header(nni_http_msg *msg, const char *key, const char *val)
{
	http_header *h;
	NNI_LIST_FOREACH (&m->hdrs, h) {
		if (strcasecmp(key, h->name) == 0) {
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

	nni_list_append(&m->hdrs, h);
	return (0);
}

const char *
nni_http_msg_get_header(nni_http_msg *msg, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (&msg->hdrs, h) {
		if (strcasecmp(h->name, key) == 0) {
			return (h->value);
		}
	}
	return (NULL);
}

int
nni_http_msg_set_data(nni_http_msg *msg, const void *data, size_t sz)
{
	int  rv;
	char buf[16];
	(void) snprintf(buf, sizeof(buf), "%d", sz);

	if ((rv = http_msg_set_header(msg, "Content-Length", buf)) != 0) {
		return (rv);
	}

	if (msg->freedata) {
		nni_free(msg->data, msg->datasz);
	}
	msg->data     = data;
	msg->datasz   = sz;
	msg->freedata = false;
	return (0);
}

int
nni_http_msg_copy_data(nni_http_msg *msg, const void *data, size_t sz)
{
	int   rv;
	void *newdata;

	if ((newdata = nni_alloc(sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_http_msg_set_data(msg, newdata, sz)) != 0) {
		nni_free(newdata, sz);
		return (rv);
	}
	msg->freedata = true;
	return (0);
}

void
nni_http_msg_get_data(nni_http_msg *msg, void **datap, size_t *szp)
{
	*datap = msg->data;
	*szp   = msg->datasz;
	return (0);
}

static const char *
http_find_header(nni_list *list, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (list, h) {
		if (strcasecmp(h->name, key) == 0) {
			return (h->value);
		}
	}
	return (NULL);
}

static int
http_parse_header(char *line, nni_list *list)
{
	key = line;
	ws_http_header *h;

	// Find separation between key and value
	if ((val = strchr(key, ":")) == NULL) {
		return (NNG_EPROTO);
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

	NNI_LIST_FOREACH (list, h) {
		if (strcasecmp(key, h->name) == 0) {
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

// http_sprintf makes either an HTTP request or an HTTP response
// object. The line is either the HTTP request line, or HTTP response line.
// Each header is dumped from the list, and finally an empty line is
// emitted.  If the buf is NULL, or the sz is 0, then a dryrun is done,
// in order to allow the caller to determine how much space is needed.
// Returns the size of the space needed, not including the terminating
// NULL byte.  Truncation occurs if the size returned is >= the requested
// size.
static size_t
http_sprintf_headers(char *buf, size_t sz, nni_list *list)
{
	size_t       l;
	size_t       rv = 0;
	http_header *h;

	if (buf == NULL) {
		sz = 0;
	}

	NNI_LIST_FOREACH (list, h) {
		l = snprintf(buf, sz, "%s: %s\r\n", h->name, h->value);
		if (buf != NULL) {
			buf += l;
		}
		sz = (sz > l) ? sz - l : 0;
		rv += l;
	}
	return (rv);
}

static int
http_req_prepare(nni_http_req *req)
{
	size_t n, len;
	char * buf;

	len = snprintf(
	    NULL, 0, "%s %s %s\r\n\r\n", req->method, req->uri, req->version);
	len += http_sprintf_headers(NULL, 0, &req->headers) + 1;

	if (len > req->headers_bufsz) {
		buf = req->headers_buf;
	} else {
		if ((buf = nni_alloc(len)) == NULL) {
			return (NNG_ENOMEM);
		}
		nni_free(req->headers_buf, req->headers_bufsz);
		req->headers_buf   = buf;
		req->headers_bufsz = len;
	}
	n = snprintf(
	    buf, len, "%s %s %s\r\n", req->method, req->uri, req->version);
	buf += n;
	len -= n;
	n = http_sprintf_headers(NULL, 0, &req->headers);
	buf += n;
	len -= n;
	snprintf(buf, len, "\r\n");
	return (0);
}

static int
http_res_prepare(nni_http_res *res)
{
	size_t n, len;
	char * buf;

	len = snprintf(NULL, 0, "%s %d %s\r\n\r\n", res->version, res->status,
	    res->message);
	len += http_sprintf_headers(NULL, 0, &res->headers) + 1;

	if (len > res->headers_bufsz) {
		buf = res->headers_buf;
	} else {
		if ((buf = nni_alloc(len)) == NULL) {
			return (NNG_ENOMEM);
		}
		nni_free(res->headers_buf, res->headers_bufsz);
		res->headers_buf   = buf;
		res->headers_bufsz = len;
	}
	n = snprintf(
	    buf, len, "%s %d %s\r\n", res->version, res->status, res->message);
	buf += n;
	len -= n;
	n = http_sprintf_headers(NULL, 0, &req->headers);
	buf += n;
	len -= n;
	snprintf(buf, len, "\r\n");
	return (0);
}

static size_t
http_sprintf_req(char *buf, size_t sz, nni_http_req *req)
{
	size_t l;
	size_t rv;

	if (buf == NULL) {
		sz = 0;
	}
	rv = 0;
	l  = snprintf(
	    buf, sz, "%s %s %s\r\n", req->method, req->uri, req->version);
	if (buf != NULL) {
		buf += l;
	}
	rv += l;
	sz = (sz > l) ? sz - l : 0;

	l = http_sprintf_headers(buf, sz, req->headers);
	if (buf != NULL) {
		buf += l;
	}
	rv += l;
	sz = (sz > l) ? sz - l : 0;

	l = snprintf(buf, sz, "\r\n");
	if (buf != NULL) {
		buf += l;
	}
	rv += l;
	return (rv);
}

static size_t
http_sprintf_res(char *buf, size_t sz, nni_http_res *res)
{
	size_t l;
	size_t rv;

	if (buf == NULL) {
		sz = 0;
	}
	rv = 0;
	l  = snprintf(
	    buf, sz, "%s %d %s\r\n", res->version, res->status, res->message);
	if (buf != NULL) {
		buf += l;
	}
	rv += l;
	sz = (sz > l) ? sz - l : 0;

	l = http_sprintf_headers(buf, sz, req->headers);
	if (buf != NULL) {
		buf += l;
	}
	rv += l;
	sz = (sz > l) ? sz - l : 0;

	l = snprintf(buf, sz, "\r\n");
	if (buf != NULL) {
		buf += l;
	}
	rv += l;
	return (rv);
}

// parse the request.  Note that this is destructive to the line.
static int
http_req_parse(char *line, nni_http_req *req)
{
	int   rv;
	char *method;
	char *uri;
	char *version;

	method = line;
	if ((uri = strchr(method, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*uri = '\0';
	uri++;

	if ((version = strchr(uri, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*version = '\0';
	version++;

	if (((rv = nni_http_req_set_method(req, method)) != 0) ||
	    ((rv = nni_http_req_set_uri(req, uri)) != 0) ||
	    ((rv = nni_http_req_set_version(req, version)) != 0)) {
		return (rv);
	}
	return (0);
}

// parse the response.  Note that this is destructive to the line.
static int
http_res_parse(char *line, nni_http_res *res)
{
	int   rv;
	char *message;
	char *codestr;
	char *version;
	int   status;

	version = line;
	if ((codestr = strchr(version, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*codestr = '\0';
	codestr++;

	if ((message = strchr(codestr, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*message = '\0';
	message++;

	status = atoi(codestr);
	if ((status < 100) || (status > 999)) {
		reutrn(NNG_EPROTO);
	}

	if (((rv = nni_http_res_set_status(status, message)) != 0) ||
	    ((rv = nni_http_res_set_version(res, version)) != 0)) {
		return (rv);
	}
	return (0);
}

static int
nni_http_msg_init(nni_http_msg **msgp, http_msgtype type)
{
	nni_http_msg *msg;
	if ((msg = NNI_ALLOC_STRUCT(msg)) == NULL) {
		return (NNG_ENOMEM);
	}
	msg->type = type;
	NNI_LIST_INIT(&msg->hdrs, http_header, node);
	msg->buf    = NULL;
	msg->bufsz  = 0;
	msg->data   = NULL;
	msg->datasz = 0;
	*msgp       = msg;
	return (0);
}

int
nni_http_msg_init_req(nni_http_msg **msgp)
{
	return (nni_http_msg_init(msgp, HTTP_MSG_REQUEST));
}

int
nni_http_msg_init_res(nni_http_msg *msgp)
{
	return (nni_http_msg_init(msgp, HTTP_MSG_RESPONSE));
}

void
nni_http_msg_fini(nni_http_msg *msg)
{
	http_header *h;

	nni_strfree(msg->meth);
	nni_strfree(msg->vers);
	nni_strfree(msg->uri);
	nni_strfree(msg->rsn);
	if (msg->bufsz) {
		nni_free(msg->buf, msg->bufsz);
	}
	if (msg->freedata && msg->datasz) {
		nni_free(msg->data, msg->datasz);
	}
	while ((h = nni_list_first(&msg->hdrs)) != NULL) {
		nni_list_remove(&msg->hdrs, h);
		if (h->name != NULL) {
			nni_strfree(h->name);
		}
		if (h->value != NULL) {
			nni_free(h->value, strlen(h->value) + 1);
		}
		NNI_FREE_STRUCT(h);
	}

	NNI_FREE_STRUCT(msg);
}

int
nni_http_msg_set_method(nni_http_msg *msg, const char *method)
{
	const char *news;
	if (msg->type != HTTP_MSG_REQUEST) {
		return (NNG_EINVAL);
	}
	if ((news = nni_strdup(method)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(msg->meth);
	msg->mth = news;
	return (0);
}

int
nni_http_msg_set_uri(nni_http_msg *msg, const char *uri)
{
	const char *news;
	if (msg->type != HTTP_MSG_REQUEST) {
		return (NNG_EINVAL);
	}
	if ((news = nni_strdup(uri)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(msg->uri);
	msg->uri = news;
	return (0);
}

int
nni_http_msg_set_version(nni_http_msg *msg, const char *vers)
{
	const char *news;
	if ((news = nni_strdup(vers)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(req->uri);
	msg->vers = news;
	return (0);
}

const char *
nni_http_msg_get_method(nni_http_msg *msg)
{
	return (msg->meth);
}

const char *
nni_http_msg_get_uri(nni_http_msg *msg)
{
	return (msg->uri);
}

const char *
nni_http_msg_get_version(nni_http_msg *msg)
{
	return (msg->version);
}

int
nni_http_msg_set_status(nni_http_msg *msg, int status, const char *reason)
{
	const char *news;
	if ((news = nni_strdup(reason)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(msg->rsn);
	msg->rsn  = reason;
	msg->code = status;
	return (0);
}

int
nni_http_msg_get_status(nni_http_msg *msg)
{
	return (msg->code);
}

const char *
nni_http_msg_get_reason(nni_http_msg *msg)
{
	return (msg->rsn);
}

// http_conn_read is called with the lock held.  It reads data into the
// aio, pulling any data that is left over in the header buffer first,
// and if none is there, then calling the underlying read.  This is the
// code that handles reads of data following the headers -- where that is
// entity content, or websocket, or some other data.
void
http_conn_read(void *arg, nni_aio *aio)
{
	nni_http_conn *conn = arg;
	size_t         resid;
	size_t         count;
	uint8_t *      src;

	count = 0;
	src   = conn->rd_buf;
	src += conn->rd_get;
	resid = conn->rd_put - conn->rd_get;
	for (i = 0; (resid != 0) && (i < aio->a_niov); i++) {
		size_t n = aio->a_iov[i].iov_len;
		if (n > resid) {
			n = resid;
		}
		memcpy(aio->a_iov[i].buf, src, n);
		src += n;
		resid -= n;
		count += n;
		conn->rd_get += n;
	}
	if (resid == 0) {
		conn->rd_get = 0;
		conn->rd_put = 0;
	}
	if (count != 0) {
		nni_aio_finish(aio, 0, count);
	} else {
		// If we didn't transfer any data, then let the underlying
		// transport move it.
		conn->rd(conn->sock, aio);
	}
}

// Reader -- this acts as a pass through, except that if we have
// residual data from the last read still around, we return that instead.
// This allows us to use this connection for websockets, without requiring
// that the websocket channel be buffered, but still letting us buffer
// the read of the request or response. (Variable size protocol headers
// are a PITA.)  This should only be used on an HTTP connection that is
// being upgraded to another protocol.  You cannot use HTTP methods on
// the connection after this point.
//
// This can also be used to support HTTP/1.0 requests, where the response
// is supposed to be read until close (when Content-Length is missing).
// Applications have to handle that themselves, if they want to support
// HTTP/1.0.
void
nni_http_conn_read(void *arg, nni_aio *aio)
{
	nni_http_conn *conn = arg;

	nni_mtx_lock(&conn->mtx);
	http_conn_read(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

// Writer.  As with nni_http_conn_write, this is used to write data on
// a connection that has been "upgraded" (e.g. transformed to websocket).
// It is an error to perform other HTTP exchanges on an connection after
// this method is called.  (This mostly exists to support websocket.)
void
nni_http_conn_write(void *arg, nni_aio *aio)
{
	nni_http_conn *conn = arg;

	nni_mtx_lock(&conn->mtx);
	conn->wr(conn->sock, aio);
	nni_mtx_unlock(&conn->mtx);
}

// http_conn_get_line just parses (tokenizes) a single line out of the
// receive buffer at a time.  The buffer used to store the data is
// subject to corruption on subsequent reads, so the caller needs to do
// something useful with it before calling this routine again.  This
// returns either 0, NNG_EAGAIN, or NNG_EPROTO.  Zero indicates a line
// was retrieved, NNG_EAGAIN indicates that a complete line is not present,
// so more data needs to be retrieved, and NNG_EPROTO indicates that
// a protocol error occurred.  We also return NNG_EPROTO if the remote
// side sent more data than we can handle in a single line.  Each line
// is expected to consist solely of printable ASCII, terminated by a CRLF.
// (Per RFC 2616.)
static int
http_conn_get_line(nni_http_conn *conn, char **bufp)
{
	int      i;
	uint8_t  lastc = 0;
	uint8_t *buf   = conn->rd_buf;
	size_t   len   = conn->rd_put - conn->rd_get;

	if (conn->rd_get != 0) {
		// If we are re-entering here, move any residual data
		// to the front, so that we can always just read from start.
		len = conn->rd_put - conn->rd_get;
		for (i = 0; i < len; i++) {
			conn->rd_buf[i] = conn->rd_buf[i + conn->rd_get];
		}
		conn->rd_put -= conn->rd_get;
		conn->rd_get = 0;
	}

	for (i = conn->rd_get; i < conn->rd_put; i++) {
		uint8_t c = buf[i];
		if (c == '\n') {
			if (lastc != '\r') {
				return (NNG_EPROTO);
			}
			*bufp        = buf + conn->rd_get;
			buf[i - 1]   = '\0';  // overwrites \r with \0
			conn->rd_get = i + 1; // advance past CRLF
			return (0);
		}
		if ((c < ' ') && (c != '\r')) {
			// No control characters allowed!
			return (NNG_EPROTO);
		}
		if (lastc == '\r') {
			// \r followed by something other than \n!
			return (NNG_EPROTO);
		}
		lastc = c;
	}

	// Not enough data.  If the buffer is not the start, then shuffle
	// the data back to start, to maximize how much room we have to
	// read into.
	if (conn->rd_get != 0) {
		for (i = 0; i < len; i++) {
			buf[i] = buf[i + conn->rd_get];
		}
		conn->rd_put -= conn->rd_get;
		conn->rd_get = 0;
	}

	// Too much data (field size too large).
	if (len == conn->rd_bufsz) {
		return (NNG_EPROTO);
	}

	// So the data is incomplete -- load some more and come back.
	return (NNG_EAGAIN);
}

static void
http_conn_close(nni_http_conn *conn)
{
	// Call with lock held.
	nni_aio *aio;

	NNI_LIST_FOREACH (&conn->wrq, aio) {
		nni_aio_cancel(aio NNG_ECLOSED);
	}
	NNI_LIST_FOREACH (&conn->rdq, aio) {
		nni_aio_cancel(aio, NNG_ECLOSED);
	}
	conn->close(conn->sock);
}

static void
http_wr_cb(void *arg)
{
	nni_http_conn *conn = arg;
	nni_aio *      aio  = conn->wr_aio;
	nni_aio *      uaio;
	int            rv;

	nni_mtx_lock(&conn->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		// We failed to complete the aio.
		if ((uaio = nni_list_first(&conn->wrq)) != NULL) {
			nni_aio_list_remove(uaio);
			nni_aio_finish_error(uaio, rv);
		}
		http_conn_close(conn);
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	n = nni_aio_count(aio);
	while (n) {
		NNI_ASSERT(aio->a_niov != 0);
		if (aio->a_iov[0].iov_len > n) {
			aio->a_iov[0].iov_len -= n;
			aio->a_iov[0].iov_buf += n;
			break;
		}
		n -= aio->a_iov[0].iov_len;
		for (int i = 0; i < aio->a_niov; i++) {
			aio->a_iov[i] = aio->a_iov[i + 1];
		}
		aio->a_niov--;
	}
	if ((aio->a_niov != 0) && (aio->a_iov[0].iov_len != 0)) {
		// We have more to transmit.
		conn->wr(conn->sock, aio);
		nni_mtx_unlock(&conn->mtx);
		return;
	}
	if ((uaio = nni_list_first(&conn->wrq)) != NULL) {
		nni_aio_list_remove(uaio);
		nni_aio_finish(uaio, 0, 0);
		http_conn_write_next(conn);
	}
	nni_mtx_unlock(&conn->mtx);
}

static void
http_rd_line(nni_http_conn *conn)
{
	int      rv;
	nni_aio *aio  = conn->rd_aio;
	nni_aio *uaio = conn->user_rd_aio;

	NNI_ASSERT(uaio != NULL);

	res = conn->res;

	for (;;) {
		nni_http_res *res;
		nni_http_res *req;
		nni_list *    hdrs;
		char *        line;
		const char *  vers;
		void **       datap;
		size_t *      sizep;

		rv = http_conn_get_line(conn, &line);
		if (rv == NNG_EAGAIN) {
			// Need more data.
			aio->a_niov = 1;
			aio->a_iov[0].iov_buf =
			    ((uint8_t *) conn->rd_buf) + conn->rd_put;
			aio->a_iov[0].iov_len = conn->rd_bufsz - conn->rd_put;
			conn->rd(conn->sock, aio);
			return;
		}
		if (rv != 0) {
			goto error;
		}

		switch (conn->read_state) {
		case HTTP_READ_REQ_LINE:
			if ((rv = http_req_parse(line, conn->req)) != 0) {
				goto error;
			}
			conn->read_state = HTTP_READ_REQ_HDRS;
			continue;

		case HTTP_READ_RES_LINE:
			if ((rv = http_res_parse(line, conn->res)) != 0) {
				goto error;
			}
			conn->read_state = HTTP_READ_RES_HDRS;
			continue;

		case HTTP_READ_REQ_HDRS:
			req   = conn->req;
			hdrs  = &req->headers;
			vers  = req->version;
			datap = &req->content;
			sizep = &req->content_size;
			if (line[0] == 0) {
				conn->read_state = HTTP_READ_REQ_DATA;
				break;
			}
			if ((rv = http_parse_header(line, hdrs)) != 0) {
				goto err;
			}
			continue;
		case HTTP_READ_RES_HDRS:
			res   = conn->res;
			hdrs  = &res->headers;
			vers  = res->version;
			datap = &res->content;
			sizep = &res->content_size;
			if (line[0] == 0) {
				conn->read_state = HTTP_READ_RES_DATA;
				break;
			}
			if ((rv = http_parse_header(line, hdrs)) != 0) {
				goto err;
			}
			continue;
		}

		NNI_ASSERT(conn->read_state == HTTP_READ_REQ_DATA ||
		    conn->read_state == HTTP_READ_RES_DATA);

		if (strcmp(vers, "HTTP/1.1") == 0) {
			int         len;
			const char *lstr =
			    http_find_header(hdrs, "content-length");
			if ((lstr != NULL) && ((len = atoi(lstr)) > 0) {

				if ((*datap = nni_alloc(len)) == NULL) {
					rv = NNG_ENOMEM;
					goto error;
				}
				aio->a_niov           = 1;
				aio->a_iov[0].iov_len = len;
				aio->a_iov[0].iov_buf = *datap;
				*sizep                = len;
				http_conn_read(conn, aio);
				return;
			}
		}

		// No data was associated, so we're done.
		*sizep            = 0;
		*datap            = NULL;
		conn->user_rd_aio = NULL;
		nni_aio_finish(uaio, 0, 0);
		return;
	}

error:
	conn->user_rd_aio = NULL;
	nni_aio_finish_error(uaio, rv);
}

static void
http_rd_cb(void *arg)
{
	nni_http_conn *conn = arg;
	nni_aio *      aio  = conn->rd_aio;
	nni_aio *      uaio;
	int            rv;

	nni_mtx_lock(&conn->mtx);
	uaio = conn->user_rd_aio;
	if (uaio == NULL) {
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	if ((rv = nni_aio_result(aio)) != 0) {
		// We failed to complete the aio.
		conn->user_rd_aio = NULL;
		nni_mtx_unlock(&conn->mtx);
		nni_aio_finish_error(uaio, rv);
		return;
	}

	NNI_ASSERT(conn->read_state != HTTP_READ_NONE);
	n = nni_aio_count(aio);

	// If we're reading data into the buffer, then we just wait until
	// that is done.
	switch (conn->read_state) {
	case HTTP_READ_REQ_LINE:
	case HTTP_READ_RES_LINE:
	case HTTP_READ_REQ_HDRS:
	case HTTP_READ_RES_HDRS:
		conn->rd_put += n;
		http_rd_line(conn);
		nni_mtx_unlock(&conn->mtx);
		return;
	case HTTP_READ_REQ_DATA:
	case HTTP_READ_RES_DATA:
		uaio->a_count += n;
		break;
	default:
		// Should never happen.
		NNI_ASSERT(0);
		break;
	}

	while (n) {
		NNI_ASSERT(aio->a_niov != 0);
		if (aio->a_iov[0].iov_len > n) {
			aio->a_iov[0].iov_len -= n;
			aio->a_iov[0].iov_buf += n;
			break;
		}
		n -= aio->a_iov[0].iov_len;
		for (int i = 0; i < aio->a_niov; i++) {
			aio->a_iov[i] = aio->a_iov[i + 1];
		}
		aio->a_niov--;
	}
	NNI_ASSERT(n >= 0);
	if (n) {
		conn->rd(conn->sock, aio);
	} else {
		NNI_ASSERT(aio->a_addr);
		conn->user_rd_aio = NULL;
		conn->read_state  = HTTP_READ_NONE;
		nni_aio_finish(uaio, 0, uaio->a_count);
	}
	nni_mtx_unlock(&conn->mtx);
}

void
http_conn_write_next(nni_http_conn *conn)
{
	nni_aio *aio;

	if ((aio = nni_list_next(&conn->wrq)) == NULL) {
		return;
	}

	for (i = 0; i < aio->a_niov; i++) {
		conn->wr_aio->a_iov[i] = aio->a_iov[i];
	}
	conn->wr(conn->sock, conn->wr_aio);
}

void
nni_http_conn_cancel(nni_aio *aio, int rv)
{
	nni_http_conn *conn = aio->a_prov_data;

	// Cancelling I/O operations on an HTTP stream is disruptive.
	// When this occurs we start by closing the stream.

	nni_mtx_lock(&conn->mtx);
	// If this AIO was active, cancel the underlying operation.
	// This will probably cause the HTTP channel to close.
	if (aio == nni_list_first(&conn->wrq)) {
		nni_aio_cancel(&conn->wr_aio, rv);
	}
	if (aio == nni_list_first(&conn->rdq)) {
		nni_aio_cancel(&conn->rd_aio, rv);
	}
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_conn_write_req(nni_http_conn *conn, nni_aio *aio, nni_http_req *req)
{
	int rv;

	if ((rv = http_req_prepare(req)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_mtx_lock(&conn->mtx);
	conn->mode = HTTP_MODE_CLIENT;
	if (nni_aio_start(aio, http_conn_cancel) != 0) {
		nni_mtx_unlock(&conn->mtx);
		return;
	}
	aio->a_niov           = 1;
	aio->a_iov[0].iov_buf = req->headers_buf;
	aio->a_iov[0].iov_len = req->headers_bufsz;
	if (res->content_size) {
		aio->a_iov[1].iov_buf = re1->content;
		aio->a_aio[1].iov_len = re1->content_size;
		aio->a_niov++;
	}
	nni_list_append(&conn->wrq, aio);
	if (nni_list_first(&conn->wrq) == aio) {
		http_conn_write_next(conn);
	}
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_conn_write_res(nni_http_conn *conn, nni_aio *aio, nni_http_res *res)
{
	int rv;

	if ((rv = http_res_prepare(res)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_mtx_lock(&conn->mtx);
	conn->mode = HTTP_MODE_SERVER;
	if (nni_aio_start(aio, http_conn_cancel) != 0) {
		nni_mtx_unlock(&conn->mtx);
		return;
	}
	aio->a_niov           = 1;
	aio->a_iov[0].iov_buf = res->headers_buf;
	aio->a_iov[0].iov_len = res->headers_bufsz;
	if (res->content_size) {
		aio->a_iov[1].iov_buf = res->content;
		aio->a_aio[1].iov_len = res->content_size;
		aio->a_niov++;
	}
	nni_list_append(&conn->wrq, aio);
	if (nni_list_first(&conn->wrq) == aio) {
		http_conn_write_next(conn);
	}
	nni_mtx_unlock(&conn->mtx);
}

int
nni_http_conn_read_req(nni_http_conn *conn, nni_aio *aio, nni_http_req *req)
{
	nni_http_req *req;

	nni_mtx_lock(&conn->mtx);
	conn->mode       = HTTP_MODE_SERVER;
	conn->read_state = HTTP_READ_REQ_LINE;
	conn->req        = req;

	if (req->content != NULL) {
		nni_free(req->content, req->len);
		req->content = NULL;
		req->len     = 0;
	}
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_conn_fini(nni_http_conn *conn)
{
	nni_aio_stop(&conn->wr_aio);
	nni_aio_stop(&conn->rd_aio);
	nni_aio_fini(&conn->wr_aio);
	nni_aio_fini(&conn->rd_aio);
	nni_mtx_fini(&conn->mtx);
	NNI_FREE_STRUCT(conn);
}

int
nni_http_conn_init(nni_http_conn **connp, nni_http_tran *tran)
{
	nni_http_conn *conn;
	int            rv;

	if ((conn == NNI_ALLOC_STRUCT(conn)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&conn->mtx);
	nni_aio_list_init(&conn->rdq);
	nni_aio_list_init(&conn->wrq);

	if (((rv = nni_aio_init(&conn->wr_aio, http_wr_cb, conn)) != 0) ||
	    ((rv = nni_aio_init(&conn->rd_aio, http_rd_cb, conn)) != 0)) {
		nni_http_conn_fini(conn);
		return (rv);
	}
	conn->rd_bufsz = HTTP_BUFSIZE;

	return (0);
}
