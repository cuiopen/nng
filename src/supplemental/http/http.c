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

typedef enum {
	HTTP_MODE_NONE   = 0,
	HTTP_MODE_CLIENT = 1,
	HTTP_MODE_SERVER = 2,
} http_conn_mode;

struct nni_http {
	void *sock;
	void (*rd)(void *, nni_aio *);
	void (*wr)(void *, nni_aio *);
	void (*close)(void *);

	bool closed;

	nni_list rdq; // high level http read requests
	nni_list wrq; // high level http write requests

	nni_aio *rd_aio; // bottom half read operations
	nni_aio *wr_aio; // bottom half write operations

	nni_mtx        mtx;
	http_conn_mode mode;

	void * rd_buf;
	size_t rd_get;
	size_t rd_put;
	size_t rd_bufsz;

	void * wr_buf;
	size_t wr_get;
	size_t wr_put;
};

#if 0
// http_conn_read is called with the lock held.  It reads data into the
// aio, pulling any data that is left over in the header buffer first,
// and if none is there, then calling the underlying read.  This is the
// code that handles reads of data following the headers -- where that is
// entity content, or websocket, or some other data.
static void
http_doread(void *arg, nni_aio *aio)
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
#endif

static void
http_close(nni_http *http)
{
	// Call with lock held.
	nni_aio *aio;

	if (http->closed) {
		return;
	}

	http->closed = true;
	if (nni_list_first(&http->wrq)) {
		nni_aio_cancel(http->wr_aio, NNG_ECLOSED);
		while ((aio = nni_list_first(&http->wrq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
	}
	if (nni_list_first(&http->rdq)) {
		nni_aio_cancel(http->rd_aio, NNG_ECLOSED);
		while ((aio = nni_list_first(&http->rdq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
	}

	http->close(http->sock);
}

#if 0
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
#endif

static void
http_rd_start(nni_http *http)
{
	nni_aio *aio;

	if (http->closed) {
		while ((aio = nni_list_first(&http->rdq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&http->rdq)) != NULL) {
		http->rd_aio->a_niov = aio->a_niov;
		for (int i = 0; i < aio->a_niov; i++) {
			http->rd_aio->a_iov[i] = aio->a_iov[i];
		}
		// Submit it down for completion.
		http->rd(http->sock, http->rd_aio);
	}
}

static void
http_rd_cb(void *arg)
{
}

static void
http_wr_start(nni_http *http)
{
	nni_aio *aio;

	if (http->closed) {
		while ((aio = nni_list_first(&http->wrq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&http->wrq)) != NULL) {
		http->wr_aio->a_niov = aio->a_niov;
		for (int i = 0; i < aio->a_niov; i++) {
			http->wr_aio->a_iov[i] = aio->a_iov[i];
		}
		// Submit it down for completion.
		http->wr(http->sock, http->wr_aio);
	}
}

static void
http_wr_cb(void *arg)
{
	nni_http *http = arg;
	nni_aio * aio  = http->wr_aio;
	nni_aio * uaio;
	int       rv;
	size_t    n;

	nni_mtx_lock(&http->mtx);

	uaio = nni_list_first(&http->wrq);

	if ((rv = nni_aio_result(aio)) != 0) {
		// We failed to complete the aio.
		if (uaio != NULL) {
			nni_aio_list_remove(uaio);
			nni_aio_finish_error(uaio, rv);
		}
		http_close(http);
		nni_mtx_unlock(&http->mtx);
		return;
	}

	n = nni_aio_count(aio);
	uaio->a_count += n;
	if (uaio->a_prov_data == NULL) {
		// For raw data, we just send partial completion notices to
		// the consumer.
		goto done;
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
	if ((aio->a_niov != 0) && (aio->a_iov[0].iov_len != 0)) {
		// We have more to transmit.
		http->wr(http->sock, aio);
		nni_mtx_unlock(&http->mtx);
		return;
	}

done:
	nni_aio_list_remove(uaio);
	nni_aio_finish(uaio, 0, uaio->a_count);

	// Start next write if another is ready.
	http_wr_start(http);

	nni_mtx_unlock(&http->mtx);
}

static void
http_wr_cancel(nni_aio *aio, int rv)
{
	nni_http *http = aio->a_prov_data;

	nni_mtx_lock(&http->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		if (aio == nni_list_first(&http->wrq)) {
			http_close(http);
		}
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&http->mtx);
}

static void
http_wr_submit(nni_http *http, nni_aio *aio)
{
	nni_mtx_lock(&http->mtx);
	if (nni_aio_start(aio, http_wr_cancel, http) != 0) {
		return;
	}
	if (http->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&http->wrq, aio);
	if (nni_list_first(&http->wrq) == aio) {
		http_wr_start(http);
	}
}

void
nni_http_write_msg(nni_http *http, nni_http_msg *msg, nni_aio *aio)
{
	int    rv;
	void * buf;
	size_t bufsz;

	if ((rv = nni_http_msg_get_buf(msg, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	aio->a_prov_extra     = msg;
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = bufsz;
	aio->a_iov[0].iov_buf = buf;

	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_write_msg_data(nni_http *http, nni_http_msg *msg, nni_aio *aio)
{
	int    rv;
	void * buf;
	size_t bufsz;
	void * data;
	size_t datasz;

	if ((rv = nni_http_msg_get_buf(msg, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_http_msg_get_data(msg, &data, &datasz);
	aio->a_prov_extra     = msg;
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = bufsz;
	aio->a_iov[0].iov_buf = buf;
	if (datasz > 0) {
		aio->a_iov[1].iov_len = datasz;
		aio->a_iov[1].iov_buf = data;
		aio->a_niov++;
	}
	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_write_data(nni_http *http, nni_http_msg *msg, nni_aio *aio)
{
	void * data;
	size_t datasz;

	nni_http_msg_get_data(msg, &data, &datasz);
	aio->a_prov_extra     = msg;
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = datasz;
	aio->a_iov[0].iov_buf = data;
	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

// Writer.  As with nni_http_conn_write, this is used to write data on
// a connection that has been "upgraded" (e.g. transformed to websocket).
// It is an error to perform other HTTP exchanges on an connection after
// this method is called.  (This mostly exists to support websocket.)
void
nni_http_write(nni_http *http, nni_aio *aio)
{
	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_fini(nni_http *http)
{
	nni_mtx_lock(&http->mtx);
	http_close(http);
	nni_mtx_unlock(&http->mtx);
	nni_aio_stop(http->wr_aio);
	nni_aio_stop(http->rd_aio);
	nni_aio_fini(http->wr_aio);
	nni_aio_fini(http->rd_aio);
	nni_mtx_fini(&http->mtx);
	NNI_FREE_STRUCT(http);
}

int
nni_http_init(nni_http **httpp, nni_http_tran *tran)
{
	nni_http *http;
	int       rv;

	if ((http = NNI_ALLOC_STRUCT(http)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&http->mtx);
	nni_aio_list_init(&http->rdq);
	nni_aio_list_init(&http->wrq);

	if (((rv = nni_aio_init(&http->wr_aio, http_wr_cb, http)) != 0) ||
	    ((rv = nni_aio_init(&http->rd_aio, http_rd_cb, http)) != 0)) {
		nni_http_fini(http);
		return (rv);
	}
	http->rd_bufsz = HTTP_BUFSIZE;
	http->rd       = tran->h_read;
	http->wr       = tran->h_write;
	http->close    = tran->h_close;
	http->sock     = tran->h_data;

	return (0);
}
