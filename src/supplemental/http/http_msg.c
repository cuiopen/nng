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
#include <strings.h>

#include "core/nng_impl.h"
#include "http.h"

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
	char *       meth;
	char *       vers;
	char *       uri;
	char *       rsn;
	nni_list     hdrs;
	char *       buf;
	size_t       bufsz;
	char *       data;
	size_t       datasz;
	bool         freedata; // if true free data when the message is freed
	size_t       datawidx;
};

int
nni_http_msg_del_header(nni_http_msg *msg, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (&msg->hdrs, h) {
		if (strcasecmp(key, h->name) == 0) {
			nni_list_remove(&msg->hdrs, h);
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
			snprintf(news, len, "%s", val);
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
	NNI_LIST_FOREACH (&msg->hdrs, h) {
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

	nni_list_append(&msg->hdrs, h);
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
	(void) snprintf(buf, sizeof(buf), "%u", (unsigned) sz);

	if ((rv = http_msg_set_header(msg, "Content-Length", buf)) != 0) {
		return (rv);
	}

	if (msg->freedata) {
		nni_free(msg->data, msg->datasz);
	}
	msg->data     = (void *) data;
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
}

static int
http_msg_parse_header(nni_http_msg *msg, char *line)
{
	http_header *h;
	char *       key = line;
	char *       val;
	char *       end;

	// Find separation between key and value
	if ((val = strchr(key, ':')) == NULL) {
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

	return (nni_http_msg_add_header(msg, key, val));
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
http_msg_prepare(nni_http_msg *m)
{
	size_t n, len;
	char * buf;
	char * vers;

	if (m->vers == NULL) {
		vers = "HTTP/1.1"; // reasonable default
	}

	switch (m->type) {
	case HTTP_MSG_REQUEST:
		if ((m->uri == NULL) || (m->meth == NULL)) {
			return (NNG_EINVAL);
		}
		len = snprintf(NULL, 0, "%s %s %s", m->meth, m->uri, vers);
		break;
	case HTTP_MSG_RESPONSE:
		if (m->rsn == NULL) {
			return (NNG_EINVAL);
		}
		len = snprintf(NULL, 0, "%s %d %s", vers, m->code, m->rsn);
		break;
	}
	len += http_sprintf_headers(NULL, 0, &m->hdrs);
	len += 5; // \r\n\r\n\0

	if (len > m->bufsz) {
		buf = m->buf;
	} else {
		if ((buf = nni_alloc(len)) == NULL) {
			return (NNG_ENOMEM);
		}
		nni_free(m->buf, m->bufsz);
		m->buf   = buf;
		m->bufsz = len;
	}
	switch (m->type) {
	case HTTP_MSG_REQUEST:
		n = snprintf(buf, len, "%s %s %s\r\n", m->meth, m->uri, vers);
		break;
	case HTTP_MSG_RESPONSE:
		n = snprintf(buf, len, "%s %d %s\r\n", vers, m->code, m->rsn);
		break;
	}
	buf += n;
	len -= n;
	n = http_sprintf_headers(buf, len, &m->hdrs);
	buf += n;
	len -= n;
	snprintf(buf, len, "\r\n");
	return (0);
}

int
nni_http_msg_get_buf(nni_http_msg *msg, void **data, size_t *szp)
{
	int rv;

	if ((msg->buf == NULL) && (rv = http_msg_prepare(msg)) != 0) {
		return (rv);
	}
	*data = msg->buf;
	*szp  = msg->bufsz;
	return (0);
}

// parse the request.  Note that this is destructive to the line.
static int
http_msg_parse_req(nni_http_msg *msg, char *line)
{
	int   rv;
	char *method;
	char *uri;
	char *version;

	NNI_ASSERT(msg->type == HTTP_MSG_REQUEST);

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

	if (((rv = nni_http_msg_set_method(msg, method)) != 0) ||
	    ((rv = nni_http_msg_set_uri(msg, uri)) != 0) ||
	    ((rv = nni_http_msg_set_version(msg, version)) != 0)) {
		return (rv);
	}
	return (0);
}

// parse the response.  Note that this is destructive to the line.
static int
http_msg_parse_res(nni_http_msg *msg, char *line)
{
	int   rv;
	char *reason;
	char *codestr;
	char *version;
	int   status;

	version = line;
	if ((codestr = strchr(version, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*codestr = '\0';
	codestr++;

	if ((reason = strchr(codestr, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*reason = '\0';
	reason++;

	status = atoi(codestr);
	if ((status < 100) || (status > 999)) {
		return (NNG_EPROTO);
	}

	if (((rv = nni_http_msg_set_status(msg, status, reason)) != 0) ||
	    ((rv = nni_http_msg_set_version(msg, version)) != 0)) {
		return (rv);
	}
	return (0);
}

static int
http_msg_init(nni_http_msg **msgp, http_msgtype type)
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
	return (http_msg_init(msgp, HTTP_MSG_REQUEST));
}

int
nni_http_msg_init_res(nni_http_msg **msgp)
{
	return (http_msg_init(msgp, HTTP_MSG_RESPONSE));
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
	char *news;
	if (msg->type != HTTP_MSG_REQUEST) {
		return (NNG_EINVAL);
	}
	if ((news = nni_strdup(method)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(msg->meth);
	msg->meth = news;
	return (0);
}

int
nni_http_msg_set_uri(nni_http_msg *msg, const char *uri)
{
	char *news;
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
	char *news;
	if ((news = nni_strdup(vers)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(msg->vers);
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
	return (msg->vers);
}

int
nni_http_msg_set_status(nni_http_msg *msg, int status, const char *reason)
{
	char *news;
	if ((news = nni_strdup(reason)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(msg->rsn);
	msg->rsn  = news;
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

static int
http_scan_line(char *buf, size_t n, size_t *lenp)
{
	size_t len;
	char   c, lc;

	lc = 0;
	for (len = 0; len < n; len++) {
		c = buf[len];
		if (c == '\n') {
			if (lc != '\r') {
				return (NNG_EPROTO);
			}
			buf[len - 1] = '\0';
			*lenp        = len;
			return (0);
		}
		// If we have a control character (other than CR), or a CR
		// followed by anything other than LF, then its an error.
		if (((c < ' ') && (c != '\r')) || (lc == '\r')) {
			return (NNG_EPROTO);
		}
		lc = c;
	}
	// Scanned the entire content, but did not find a line.
	return (NNG_EAGAIN);
}

// http_msg_parse parses a message, and optionally the attached entity/data.
static int
http_msg_parse(nni_http_msg *msg, char *buf, size_t n, size_t *lenp, bool dat)
{
	size_t len = 0;
	size_t cnt;
	char * line;
	int    rv = 0;
	for (;;) {
		if (msg->datasz) {
			cnt = msg->datasz - msg->datawidx;
			if (cnt > n) { // We need more than is available.
				cnt = n;
				rv  = NNG_EAGAIN;
			}
			memcpy(msg->data + msg->datawidx, buf, cnt);
			msg->datawidx += cnt;
			len += cnt;
			break;
		}

		if ((rv = http_scan_line(buf, n, &cnt)) != 0) {
			break;
		}

		len += cnt;
		line = buf;
		buf += cnt;
		n -= cnt;

		// If that is the end of the headers, then start scanning
		// for data, if the caller asked us to, and are an HTTP/1.1
		// request.
		if (*line == '\0') {
			const char *cls;
			int         clen;
			if ((!dat) || (strcmp(msg->vers, "HTTP/1.1") != 0)) {
				break;
			}
			cls = nni_http_msg_get_header(msg, "Content-Length");
			if ((cls == NULL) || ((clen = atoi(cls)) < 1)) {
				break;
			}
			if ((msg->data = nni_alloc(clen)) == NULL) {
				rv = NNG_ENOMEM;
				break;
			}
			msg->datasz   = (size_t) cls;
			msg->datawidx = 0;
			continue;
		}

		if (msg->vers != NULL) {
			rv = http_msg_parse_header(msg, line);
		} else if (msg->type == HTTP_MSG_REQUEST) {
			rv = http_msg_parse_req(msg, line);
		} else {
			NNI_ASSERT(msg->type == HTTP_MSG_RESPONSE);
			rv = http_msg_parse_res(msg, line);
		}

		if (rv != 0) {
			break;
		}
	}

	*lenp = len;
	return (rv);
}

// Parse a message from the buffer.  This parses consumes only the headers,
// leaving any entity remaining.  The caller is responsible for consuming
// the entity.  This returns 0 if the entire message is parsed, NNG_EAGAIN
// if more data is needed, or another error (e.g. NNG_EPROTO, NNG_ENOMEM).
// The number of bytes consumed from the input will be returned in *lenp.
int
nni_http_msg_parse(nni_http_msg *msg, char *buf, size_t n, size_t *lenp)
{
	return (http_msg_parse(msg, buf, n, lenp, false));
}

// Parse an entire message, including the entity data.  The entity is
// parsed provided that the message was an HTTP/1.1 message.  (No support
// for legacy HTTP/1.0 because that means read-until-close.)  The same
// calling conventions as nni_http_msg_parse apply otherwise.
int
nni_http_msg_parse_data(nni_http_msg *msg, char *buf, size_t n, size_t *lenp)
{
	return (http_msg_parse(msg, buf, n, lenp, false));
}
