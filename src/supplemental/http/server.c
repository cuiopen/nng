//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"
#include "http.h"

typedef struct http_handler {
	nni_list_node node;
	void *        h_arg;
	char *        h_path;
	char *        h_method;
	char *        h_host;
	bool          h_upgrader;
	bool          h_is_dir;
	void (*h_cb)(nni_aio *);
} http_handler;

typedef struct http_sconn {
	nni_list_node    node;
	nni_http *       http;
	nni_http_server *server;
	nni_http_req *   req;
	nni_http_res *   res;
	bool             close;
	nni_aio *        cbaio;
	nni_aio *        rxaio;
	nni_aio *        txaio;
	nni_aio *        txdataio;
	nni_http_tran    tran;
} http_sconn;

struct nni_http_server {
	nng_sockaddr     addr;
	nni_list         handlers;
	nni_list         conns;
	nni_mtx          mtx;
	bool             closed;
	bool             tls;
	nni_aio *        accaio;
	nni_plat_tcp_ep *tep;
};

static void
http_sconn_close(http_sconn *sc)
{
	nni_http_server *s;
	if ((s = sc->server) != NULL) {
		nni_mtx_lock(&s->mtx);
		nni_list_node_remove(&sc->node);
		nni_mtx_unlock(&s->mtx);
	}
	nni_aio_stop(sc->rxaio);
	nni_aio_stop(sc->txaio);
	nni_aio_stop(sc->txdataio);
	nni_aio_stop(sc->cbaio);
	nni_http_close(sc->http);
	nni_http_fini(sc->http);
	if (sc->req != NULL) {
		nni_http_req_fini(sc->req);
	}
	if (sc->res != NULL) {
		nni_http_res_fini(sc->res);
		sc->res = NULL;
	}
	nni_aio_fini(sc->rxaio);
	nni_aio_fini(sc->txaio);
	nni_aio_fini(sc->txdataio);
	nni_aio_fini(sc->cbaio);
	NNI_FREE_STRUCT(sc);
}

static void
http_sconn_txdatdone(void *arg)
{
	http_sconn *sc  = arg;
	nni_aio *   aio = sc->txdataio;

	if (nni_aio_result(aio) != 0) {
		http_sconn_close(sc);
		return;
	}

	if (sc->close) {
		http_sconn_close(sc);
		return;
	}

	if (sc->res != NULL) {
		nni_http_res_fini(sc->res);
		sc->res = NULL;
	}

	nni_http_req_reset(sc->req);
	nni_http_read_req(sc->http, sc->req, sc->rxaio);
}

static void
http_sconn_txdone(void *arg)
{
	http_sconn *sc  = arg;
	nni_aio *   aio = sc->txaio;
	const char *val;
	int         rv;
	bool        close;
	void *      data;
	size_t      size;

	if ((rv = nni_aio_result(aio)) != 0) {
		http_sconn_close(sc);
		return;
	}

	// For HEAD requests, we just treat like "GET" but don't send
	// the data.  (Required per HTTP.)
	if (strcmp(nni_http_req_get_method(sc->req), "HEAD") == 0) {
		size = 0;
	} else {
		nni_http_res_get_data(sc->res, data, &size);
	}
	if (size) {
		// Submit data.
		sc->txdataio->a_niov           = 1;
		sc->txdataio->a_iov[0].iov_buf = data;
		sc->txdataio->a_iov[0].iov_len = size;
		nni_http_write_full(sc->http, sc->txdataio);
		return;
	}

	if (sc->close) {
		http_sconn_close(sc);
		return;
	}

	if (sc->res != NULL) {
		nni_http_res_fini(sc->res);
		sc->res = NULL;
	}
	nni_http_req_reset(sc->req);
	nni_http_read_req(sc->http, sc->req, sc->rxaio);
}

static char
http_hexval(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return (c - '0');
	}
	if ((c >= 'a') && (c <= 'f')) {
		return ((c - 'a') + 10);
	}
	if ((c >= 'A') && (c <= 'F')) {
		return ((c - 'A') + 10);
	}
	return (0);
}

static char *
http_uri_canonify(char *path)
{
	char *tmp;
	char *dst;

	// Chomp off query string.
	if ((tmp = strchr(path, '?')) != NULL) {
		*tmp = '\0';
	}
	// If the URI was absolute, make it relative.
	if ((strncasecmp(path, "http://", strlen("http://")) == 0) ||
	    (strncasecmp(path, "https://", strlen("https://")) == 0)) {
		// Skip past the ://
		path = strchr(path, ':');
		path += 3;

		// scan for the end of the host, distinguished by a /
		// path delimiter.  There might not be one, in which case
		// the whole thing is the host and we assume the path is
		// just /.
		if ((path = strchr(path, '/')) == NULL) {
			return ("/");
		}
	}

	// Now we have to unescape things.  Unescaping is a shrinking
	// operation (strictly), so this is safe.  This is just URL decode.
	// Note that paths with an embedded NUL are going to be treated as
	// though truncated.  Don't be that guy that sends %00 in a URL.
	tmp = path;
	dst = path;
	while (*tmp != '\0') {
		char c;
		if ((c = *tmp) != '%') {
			*dst++ = c;
			tmp++;
			continue;
		}
		if (isxdigit(tmp[1]) && isxdigit(tmp[2])) {
			c = http_hexval(tmp[1]);
			c *= 16;
			c += http_hexval(tmp[2]);
			*dst++ = c;
			tmp += 3;
		}
		// garbage in, garbage out
		*dst++ = c;
		tmp++;
	}
	*dst = '\0';
	return (path);
}

static void
http_sconn_error(http_sconn *sc, int err)
{
	// XXX: add handling for overrides.
	char *rsn;
	char  rsnbuf[80];
	char  html[1024];

	switch (err) {
	case NNI_HTTP_STATUS_BAD_REQUEST:
		rsn = "Bad request";
		break;
	case NNI_HTTP_STATUS_UNAUTHORIZED:
		rsn = "Unauthorized";
		break;
	case NNI_HTTP_STATUS_PAYMENT_REQUIRED:
		rsn = "Payment required";
		break;
	case NNI_HTTP_STATUS_NOT_FOUND:
		rsn = "Resource not found";
		break;
	case NNI_HTTP_STATUS_METHOD_NOT_ALLOWED:
		rsn = "Method not allowed";
		break;
	case NNI_HTTP_STATUS_NOT_ACCEPTABLE:
		rsn = "Not acceptable";
		break;
	default:
		snprintf(rsnbuf, sizeof(rsnbuf), "HTTP error code %d", err);
		rsn = rsnbuf;
		break;
	}

	// very simple builtin error page
	snprintf(html, sizeof(html),
	    "<head><title>%d %s<title></head>"
	    "<body><h1 align=\"center\">"
	    "<span style=\"font-size: 36px; border-radius: 5px; "
	    "background-color: black; color: white; padding: 7px; "
	    "font-family: Arial, sans serif;\">%d</span></h1>"
	    "<p align=\"center\">"
	    "<span style=\"font-size: 24px; font-family: Arial, sans serif;\">"
	    "%s</span></p></body>",
	    err, rsn, err, rsn);

	nni_http_res_set_status(sc->res, err, rsn);
	nni_http_res_copy_data(sc->res, html, strlen(html));
	nni_http_res_set_version(sc->res, "HTTP/1.1");
	nni_http_res_set_header(
	    sc->res, "Content-Type", "text/html; charset=UTF-8");
	// We could set the date, but we don't necessarily have a portable
	// way to get the time of day.

	nni_http_write_res(sc->http, sc->res, sc->txaio);
}

static void
http_sconn_rxdone(void *arg)
{
	http_sconn *     sc  = arg;
	nni_http_server *s   = sc->server;
	nni_aio *        aio = sc->rxaio;
	int              rv;
	http_handler *   h;
	const char *     val;
	nni_http_req *   req = sc->req;
	char *           uri;
	size_t           urisz;
	char *           path;
	char *           tmp;
	bool             badmeth;

	if ((rv = nni_aio_result(aio)) != 0) {
		http_sconn_close(sc);
		return;
	}

	// Validate the request -- it has to at least look like HTTP 1.x
	// We flatly refuse to deal with HTTP 0.9, and we can't cope with
	// HTTP/2.
	if ((val = nni_http_req_get_version(req)) == NULL) {
		sc->close = true;
		http_sconn_error(sc, NNI_HTTP_STATUS_BAD_REQUEST);
		return;
	}
	if (strncmp(val, "HTTP/1.", 7) != 0) {
		sc->close = true;
		http_sconn_error(sc, NNI_HTTP_STATUS_HTTP_VERSION_NOT_SUPP);
		return;
	}
	if (strcmp(val, "HTTP/1.1") != 0) {
		// We treat HTTP/1.0 connections as non-persistent.
		// No effort is made to handle "persistent" HTTP/1.0
		// since that was not standard.  (Everyone is at 1.1 now
		// anyways.)
		sc->close = true;
	}

	// If the connection was 1.0, or a connection: close was requested,
	// then mark this close on our end.
	if ((val = nni_http_req_get_header(req, "Connection")) != NULL) {
		// HTTP 1.1 says these have to be case insensitive (7230)
		if (nni_strcasestr(val, "close") != NULL) {
			// In theory this could falsely match some other weird
			// connection header that included the word close not
			// as part of a whole token.  No such legal definitions
			// exist, and so anyone who does that gets what they
			// deserve. (Fairly harmless actually, since it only
			// prevents persistent connections.)
			sc->close = true;
		}
	}

	val   = nni_http_req_get_uri(req);
	urisz = strlen(val) + 1;
	if ((uri = nni_alloc(urisz)) == NULL) {
		http_sconn_close(sc); // out of memory
		return;
	}
	strncpy(uri, val, urisz);
	path = http_uri_canonify(uri);

	NNI_LIST_FOREACH (&s->handlers, h) {
		size_t len;
		if (h->h_host != NULL) {
			val = nni_http_req_get_header(req, "Host");
			if ((val == NULL) ||
			    (strcasecmp(val, h->h_host) != 0)) {
				continue;
			}
		}

		NNI_ASSERT(h->h_method != NULL);

		len = strlen(h->h_path);
		if (strncmp(path, h->h_path, len) != 0) {
			continue;
		}
		switch (path[len]) {
		case '\0':
			break;
		case '/':
			if ((path[len + 1] != '\0') && (!h->h_is_dir)) {
				// trailing component and not a directory.
				// Note that this should force a failure.
				continue;
			}
			break;
		default:
			continue; // some other substring, not matched.
		}

		// So, what about the method?
		val = nni_http_req_get_method(req);
		if (strcmp(val, h->h_method) == 0) {
			break;
		}
		// HEAD is remapped to GET.
		if ((strcmp(val, "HEAD") == 0) &&
		    (strcmp(h->h_method, "GET") == 0)) {
			break;
		}
		badmeth = 1;
	}

	nni_free(uri, urisz);
	if (h == NULL) {
		if (badmeth) {
			http_sconn_error(
			    sc, NNI_HTTP_STATUS_METHOD_NOT_ALLOWED);
		} else {
			http_sconn_error(sc, NNI_HTTP_STATUS_NOT_FOUND);
		}
		return;
	}

	nni_aio_set_input(sc->cbaio, 0, sc->http);
	nni_aio_set_input(sc->cbaio, 1, sc->req);
	nni_aio_set_input(sc->cbaio, 2, h->h_arg);
	h->h_cb(sc->cbaio);
}

static void
http_sconn_cbdone(void *arg)
{
	http_sconn *  sc  = arg;
	nni_aio *     aio = sc->cbaio;
	nni_http_res *res;

	if (nni_aio_result(aio) != 0) {
		// Hard close, no further feedback.
		http_sconn_close(sc);
		return;
	}

	res = nni_aio_get_output(aio, 0);
	if (res != NULL) {

		const char *val;
		val = nni_http_res_get_header(res, "Connection");
		if ((val != NULL) && (strstr(val, "close") != NULL)) {
			sc->close = true;
		}
		if (sc->close) {
			nni_http_res_set_header(res, "Connection", "close");
		}
		sc->res = res;
		nni_http_write_res(sc->http, res, sc->txaio);
	} else if (sc->close) {
		http_sconn_close(sc);
	} else {
		// Presumably client already sent a response.
		// Wait for another request.
		nni_http_req_reset(sc->req);
		nni_http_read_req(sc->http, sc->req, sc->rxaio);
	}
}

static int
http_sconn_init(http_sconn **scp, nni_plat_tcp_pipe *tcp)
{
	http_sconn *sc;
	int         rv;

	if ((sc = NNI_ALLOC_STRUCT(sc)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_http_req_init(&sc->req)) != 0) ||
	    ((rv = nni_aio_init(&sc->rxaio, http_sconn_rxdone, sc)) != 0) ||
	    ((rv = nni_aio_init(&sc->txaio, http_sconn_txdone, sc)) != 0) ||
	    ((rv = nni_aio_init(&sc->txdataio, http_sconn_txdatdone, sc)) !=
	        0) ||
	    ((rv = nni_aio_init(&sc->cbaio, http_sconn_cbdone, sc)) != 0)) {
		// Can't even accept the incoming request.  Hard close.
		http_sconn_close(sc);
		return (rv);
	}
	// XXX: for HTTPS we would then try to do the TLS negotiation here.
	// That would use a different set of tran values.

	sc->tran.h_data  = tcp;
	sc->tran.h_read  = (void *) nni_plat_tcp_pipe_recv;
	sc->tran.h_write = (void *) nni_plat_tcp_pipe_send;
	sc->tran.h_close = (void *) nni_plat_tcp_pipe_fini; // close implied

	if ((rv = nni_http_init(&sc->http, &sc->tran)) != 0) {
		http_sconn_close(sc);
		return (rv);
	}
	*scp = sc;
	return (0);
}

static void
http_server_acccb(void *arg)
{
	nni_http_server *  s   = arg;
	nni_aio *          aio = s->accaio;
	nni_plat_tcp_pipe *tcp;
	http_sconn *       sc;

	if (nni_aio_result(aio) != 0) {
		// XXX: now what?
	}
	tcp = nni_aio_get_pipe(aio);
	if (http_sconn_init(&sc, tcp) != 0) {
		nni_plat_tcp_pipe_close(tcp);
		nni_plat_tcp_pipe_fini(tcp);
		return;
	}
	nni_mtx_lock(&s->mtx);
	if (s->closed) {
		http_sconn_close(sc);
	} else {
		nni_list_append(&s->conns, sc);
		nni_http_read_req(sc->http, sc->req, sc->rxaio);
		nni_plat_tcp_ep_accept(s->tep, s->accaio);
	}
	nni_mtx_unlock(&s->mtx);
}

void
nni_http_server_fini(nni_http_server *s)
{
	nni_http_server_stop(s);
	nni_aio_fini(s->accaio);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

int
nni_http_server_init(nni_http_server **serverp)
{
	nni_http_server *s;
	int              rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	NNI_LIST_INIT(&s->handlers, http_handler, node);
	NNI_LIST_INIT(&s->conns, http_sconn, node);
	if ((rv = nni_aio_init(&s->accaio, http_server_acccb, s)) != 0) {
		nni_http_server_fini(s);
		return (rv);
	}
	*serverp = s;
	return (0);
}

int
nni_http_server_start(nni_http_server *s, nng_sockaddr *addr)
{
	int rv;

	s->addr = *addr;
	rv = nni_plat_tcp_ep_init(&s->tep, &s->addr, NULL, NNI_EP_MODE_LISTEN);
	if (rv != 0) {
		return (rv);
	}
	if ((rv = nni_plat_tcp_ep_listen(s->tep)) != 0) {
		nni_plat_tcp_ep_fini(s->tep);
		s->tep = NULL;
		return (rv);
	}
	nni_plat_tcp_ep_accept(s->tep, s->accaio);
}

void
nni_http_server_stop(nni_http_server *s)
{
	http_sconn *sc;

	nni_mtx_lock(&s->mtx);
	if (s->closed) {
		nni_mtx_unlock(&s->mtx);
		return;
	}

	s->closed = true;
	// Close the TCP endpoint that is listening.
	nni_plat_tcp_ep_close(s->tep);

	// This marks the server as "shutting down" -- existing
	// connections finish their activity and close.
	//
	// XXX: figure out how to shut down connections that are
	// blocked waiting to receive a request.  We won't do this for
	// upgraded connections...
	NNI_LIST_FOREACH (&s->conns, sc) {
		sc->close = true;
	}
	nni_mtx_unlock(&s->mtx);
}

static void
http_handler_fini(http_handler *h)
{
	nni_strfree(h->h_path);
	nni_strfree(h->h_host);
	nni_strfree(h->h_method);
	NNI_FREE_STRUCT(h);
}

int
nni_http_server_add_handler(
    void **hp, nni_http_server *s, nni_http_handler *hh, void *arg)
{
	http_handler *h, *h2;
	size_t        l1, l2;

	// Must have a legal method (and not one that is HEAD), path,
	// and handler.  (The reason HEAD is verboten is that we supply
	// it automatically as part of GET support.)
	if ((hh->h_method == NULL) || (hh->h_path == NULL) ||
	    (hh->h_cb == NULL) || (strcmp(hh->h_method, "HEAD") == 0)) {
		return (NNG_EINVAL);
	}
	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	h->h_arg    = arg;
	h->h_cb     = hh->h_cb;
	h->h_is_dir = hh->h_is_dir;

	if ((hh->h_host != NULL) &&
	    ((h->h_host = nni_strdup(hh->h_host)) == NULL)) {
		http_handler_fini(h);
		return (NNG_ENOMEM);
	}

	if (((h->h_method = nni_strdup(hh->h_method)) == NULL) ||
	    ((h->h_path = nni_strdup(hh->h_path)) == NULL)) {
		http_handler_fini(h);
		return (NNG_ENOMEM);
	}

	l1 = strlen(h->h_path);
	// Chop off trailing "/"
	while (l1 > 0) {
		if (h->h_path[l1 - 1] != '/') {
			break;
		}
		l1--;
		h->h_path[l1] = '\0';
	}

	nni_mtx_lock(&s->mtx);
	// General rule for finding a conflict is that if either string
	// is a strict substring of the other, then we have a
	// collision.  (But only if the methods match, and the host
	// matches.  Note that a wild card host matches both.
	NNI_LIST_FOREACH (&s->handlers, h2) {
		if ((h2->h_host != NULL) && (h->h_host != NULL) &&
		    (strcasecmp(h2->h_host, h->h_host) != 0)) {
			// Hosts don't match, so we are safe.
			continue;
		}
		if (strcmp(h2->h_method, h->h_method) != 0) {
			// Different methods, so again we are fine.
			continue;
		}
		l2 = strlen(h2->h_path);
		if (l1 < l2) {
			l2 = l1;
		}
		if (strncmp(h2->h_path, h->h_path, l2) == 0) {
			// Path collision.  NNG_EADDRINUSE.
			http_handler_fini(h);
			return (NNG_EADDRINUSE);
		}
	}
	nni_list_append(&s->handlers, h);
	nni_mtx_unlock(&s->mtx);
	*hp = h;
	return (0);
}