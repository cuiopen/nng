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
#include <string.h>

#include "core/nng_impl.h"
#include "http.h"

// We insist that individual headers fit in 8K.
// If you need more than that, you need something we can't do.
#define HTTP_BUFSIZE 8192

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

	nni_mtx mtx;

	char * rd_buf;
	size_t rd_get;
	size_t rd_put;
	size_t rd_bufsz;
};

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

void
nni_http_close(nni_http *http)
{
	nni_mtx_lock(&http->mtx);
	http_close(http);
	nni_mtx_unlock(&http->mtx);
}

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

		// If we already have data in the read buffer, then
		// just "finish" the lower aio using the residual.
		if (http->rd_put > http->rd_get) {
			// The "size" we finish the underlying AIO is
			// zero, because we haven't transferred any new data.
			nni_aio_finish(http->rd_aio, 0, 0);
		} else {
			// Submit it down for completion.
			http->rd(http->sock, http->rd_aio);
		}
	}
}

static void
http_rd_cb(void *arg)
{
	nni_http *    http = arg;
	nni_aio *     aio  = http->rd_aio;
	nni_aio *     uaio;
	nni_http_msg *msg;
	size_t        cnt;
	size_t        n;
	int           rv;

	nni_mtx_lock(&http->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	n = nni_aio_count(aio);

	// If this was a zero copy read, then just "pass" the result through.
	if (aio->a_iov[0].iov_buf < (uint8_t *) http->rd_buf ||
	    aio->a_iov[0].iov_buf >=
	        (uint8_t *) http->rd_buf + http->rd_bufsz) {
		NNI_ASSERT(http->rd_get == 0);
		NNI_ASSERT(http->rd_put == 0);
		uaio = nni_list_first(&http->rdq);
		// The uaio has to be present, since we are doing a pass-thru
		// read. (Otherwise we could be reading into a buffer that
		// is not valid!)
		NNI_ASSERT(uaio != NULL);
		nni_aio_list_remove(uaio);
		nni_aio_finish(uaio, 0, n);
		http_rd_start(http);
		nni_mtx_unlock(&http->mtx);
		return;
	}

	NNI_ASSERT(aio->a_niov == 1);
	http->rd_put += n;
	NNI_ASSERT(http->rd_put <= http->rd_bufsz);
	NNI_ASSERT(http->rd_put >= http->rd_get);

	// If this wasn't a message read, then we just consume the requested
	// amount of data (or whatever we have left) out of the buffer.
	cnt = http->rd_put - http->rd_get;
	while (cnt > 0) {

		if ((uaio = nni_list_first(&http->rdq)) == NULL) {
			// Left over data.  Leave it for next read.
			nni_mtx_unlock(&http->mtx);
			return;
		}
		if ((msg = uaio->a_prov_extra) == NULL) {
			uaio->a_count = 0;
			for (int i = 0; n > 0 && i < uaio->a_niov; i++) {
				n = uaio->a_iov[i].iov_len;
				if (n > cnt) {
					n = cnt;
				}
				memcpy(uaio->a_iov[i].iov_buf,
				    http->rd_buf + http->rd_get, n);
				http->rd_get += n;
				cnt -= n;
				uaio->a_count += n;
			}
			nni_aio_list_remove(uaio);
			nni_aio_finish(uaio, 0, uaio->a_count);
			continue;
		}

		// NB: When handling AIOs for message transfers, the actual
		// iov submitted with the user AIO will be ignored. Instead
		// we load the message data and use the parser to read data
		// from the connection's buffer in place.

		rv = nni_http_msg_parse(
		    msg, http->rd_buf + http->rd_get, cnt, &n);
		http->rd_get += n; // Unconditionally -- EGAIN does consume.
		switch (rv) {
		case 0: // Completely read the message.
			nni_aio_list_remove(uaio);
			nni_aio_finish(uaio, 0, 0);
			continue;
		case NNG_EAGAIN: // We need more data.
			// Schedule another read.  But first make sure
			// that we move the present data to the end so that
			// we have as much room as possible.
			if (http->rd_get != 0) {
				for (int i = 0; i < cnt; i++) {
					http->rd_buf[i] =
					    http->rd_buf[i + http->rd_get];
				}
				http->rd_get = 0;
				http->rd_put = cnt;
			}
			if (http->rd_put >= http->rd_bufsz) {
				rv = NNG_EPROTO; // HTTP data line too big.
				goto error;
			}
			aio->a_niov           = 0;
			aio->a_iov[0].iov_buf = (uint8_t *) http->rd_buf + cnt;
			aio->a_iov[0].iov_len = http->rd_bufsz - cnt;
			http->rd(http->sock, aio);
			nni_mtx_unlock(&http->mtx);
			return;
		default:
			// Protocol error (bad parse).
			goto error;
		}
	}

	// We consumed all data, possibly start reading some more.
	http_rd_start(http);
	nni_mtx_unlock(&http->mtx);
	return;

error:
	if ((uaio = nni_list_first(&http->rdq)) != NULL) {
		nni_aio_list_remove(uaio);
		nni_aio_finish_error(uaio, rv);
	}
	http_close(http);
	nni_mtx_unlock(&http->mtx);
}

static void
http_rd_cancel(nni_aio *aio, int rv)
{
	nni_http *http = aio->a_prov_data;

	nni_mtx_lock(&http->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		if (aio == nni_list_first(&http->rdq)) {
			http_close(http);
		}
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&http->mtx);
}

static void
http_rd_submit(nni_http *http, nni_aio *aio)
{
	if (nni_aio_start(aio, http_rd_cancel, http) != 0) {
		return;
	}
	if (http->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&http->rdq, aio);
	if (nni_list_first(&http->rdq) == aio) {
		http_rd_start(http);
	}
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
	if (uaio->a_prov_extra == NULL) {
		// For raw data, we just send partial completion
		// notices to the consumer.
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
nni_http_read_msg(nni_http *http, nni_http_msg *msg, nni_aio *aio)
{
	aio->a_prov_extra     = msg;
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = http->rd_bufsz;
	aio->a_iov[0].iov_buf = (void *) http->rd_buf;

	nni_mtx_lock(&http->mtx);
	http_rd_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
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
// a connection that has been "upgraded" (e.g. transformed to
// websocket). It is an error to perform other HTTP exchanges on an
// connection after this method is called.  (This mostly exists to
// support websocket.)
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
	nni_free(http->rd_buf, http->rd_bufsz);
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
	http->rd_bufsz = HTTP_BUFSIZE;
	if ((http->rd_buf = nni_alloc(http->rd_bufsz)) == NULL) {
		NNI_FREE_STRUCT(http);
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

	*httpp = http;

	return (0);
}
