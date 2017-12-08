//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdarg.h>
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

typedef struct http_entity {
	char * data;
	size_t size; // allocated/expected size
	size_t len;  // current length
	bool   own;  // if true, data is "ours", and should be freed
} http_entity;

typedef enum { HTTP_MSG_REQUEST, HTTP_MSG_RESPONSE } http_msgtype;

typedef struct nni_http_msg {
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
} http_msg;

struct nni_http_req {
	nni_list    hdrs;
	http_entity data;
	char *      meth;
	char *      uri;
	char *      vers;
	char *      buf;
	size_t      bufsz;
};

struct nni_http_res {
	nni_list    hdrs;
	http_entity data;
	int         code;
	char *      rsn;
	char *      vers;
	char *      buf;
	size_t      bufsz;
};

static int
http_set_string(char **strp, const char *val)
{
	char *news;
	if ((news = nni_strdup(val)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(*strp);
	*strp = news;
	return (0);
}

static void
http_headers_reset(nni_list *hdrs)
{
	http_header *h;
	while ((h = nni_list_first(hdrs)) != NULL) {
		nni_list_remove(hdrs, h);
		if (h->name != NULL) {
			nni_strfree(h->name);
		}
		if (h->value != NULL) {
			nni_free(h->value, strlen(h->value) + 1);
		}
		NNI_FREE_STRUCT(h);
	}
}

static void
http_entity_reset(http_entity *entity)
{
	if (entity->own && entity->size) {
		nni_free(entity->data, entity->size);
	}
	entity->data = NULL;
	entity->size = 0;
	entity->own  = false;
}

void
nni_http_req_reset(nni_http_req *req)
{
	http_headers_reset(&req->hdrs);
	http_entity_reset(&req->data);
	nni_strfree(req->vers);
	nni_strfree(req->meth);
	nni_strfree(req->uri);
	req->vers = req->meth = req->uri = NULL;
	if (req->bufsz) {
		req->buf[0] = '\0';
	}
}

void
nni_http_res_reset(nni_http_res *res)
{
	http_headers_reset(&res->hdrs);
	http_entity_reset(&res->data);
	nni_strfree(res->rsn);
	res->code = 0;
	if (res->bufsz) {
		res->buf[0] = '\0';
	}
}

void
nni_http_req_fini(nni_http_req *req)
{
	http_header *h;

	nni_http_req_reset(req);
	if (req->bufsz) {
		nni_free(req->buf, req->bufsz);
	}
	NNI_FREE_STRUCT(req);
}

void
nni_http_res_fini(nni_http_res *res)
{
	http_header *h;

	nni_http_res_reset(res);
	if (res->bufsz) {
		nni_free(res->buf, res->bufsz);
	}
	NNI_FREE_STRUCT(res);
}

static int
http_del_header(nni_list *hdrs, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (strcasecmp(key, h->name) == 0) {
			nni_list_remove(hdrs, h);
			nni_strfree(h->name);
			nni_free(h->value, strlen(h->value) + 1);
			NNI_FREE_STRUCT(h);
			return (0);
		}
	}
	return (NNG_ENOENT);
}

int
nni_req_del_header(nni_http_req *req, const char *key)
{
	return (http_del_header(&req->hdrs, key));
}

int
nni_res_del_header(nni_http_res *res, const char *key)
{
	return (http_del_header(&res->hdrs, key));
}

static int
http_set_header(nni_list *hdrs, const char *key, const char *val)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
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
	strncpy(h->value, val, strlen(val) + 1);
	nni_list_append(hdrs, h);
	return (0);
}

int
nni_http_req_set_header(nni_http_req *req, const char *key, const char *val)
{
	return (http_set_header(&req->hdrs, key, val));
}

int
nni_http_res_set_header(nni_http_res *res, const char *key, const char *val)
{
	return (http_set_header(&res->hdrs, key, val));
}

static int
http_add_header(nni_list *hdrs, const char *key, const char *val)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
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
	strncpy(h->value, val, strlen(val) + 1);
	nni_list_append(hdrs, h);
	return (0);
}

int
nni_http_req_add_header(nni_http_req *req, const char *key, const char *val)
{
	return (http_add_header(&req->hdrs, key, val));
}

int
nni_http_res_add_header(nni_http_res *res, const char *key, const char *val)
{
	return (http_add_header(&res->hdrs, key, val));
}

static const char *
http_get_header(nni_list *hdrs, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (strcasecmp(h->name, key) == 0) {
			return (h->value);
		}
	}
	return (NULL);
}

const char *
nni_http_req_get_header(nni_http_req *req, const char *key)
{
	return (http_get_header(&req->hdrs, key));
}

const char *
nni_http_res_get_header(nni_http_res *res, const char *key)
{
	return (http_get_header(&res->hdrs, key));
}

// http_entity_set_data sets the entity, but does not update the
// content-length header.
static void
http_entity_set_data(http_entity *entity, const void *data, size_t size)
{
	if (entity->own) {
		nni_free(entity->data, entity->size);
	}
	entity->data = (void *) data;
	entity->size = size;
	entity->own  = false;
}

static int
http_entity_copy_data(http_entity *entity, const void *data, size_t size)
{
	void *newdata;
	if ((newdata = nni_alloc(size)) == NULL) {
		return (NNG_ENOMEM);
	}
	http_entity_set_data(entity, newdata, size);
	entity->own = true;
	return (0);
}

static int
http_set_content_length(http_entity *entity, nni_list *hdrs)
{
	char buf[16];
	(void) snprintf(buf, sizeof(buf), "%u", (unsigned) entity->size);
	return (http_set_header(hdrs, "Content-Length", buf));
}

static void
http_entity_get_data(http_entity *entity, void **datap, size_t *sizep)
{
	*datap = entity->data;
	*sizep = entity->size;
}

void
http_req_get_data(nni_http_req *req, void **datap, size_t *sizep)
{
	http_entity_get_data(&req->data, datap, sizep);
}

void
http_res_get_data(nni_http_res *res, void **datap, size_t *sizep)
{
	http_entity_get_data(&res->data, datap, sizep);
}

int
nni_http_req_set_data(nni_http_req *req, const void *data, size_t size)
{
	http_entity_set_data(&req->data, data, size);
	return (http_set_content_length(&req->data, &req->hdrs));
}

int
nni_http_req_copy_data(nni_http_req *req, const void *data, size_t size)
{
	int rv;

	if (((rv = http_entity_copy_data(&req->data, data, size)) != 0) ||
	    ((rv = http_set_content_length(&req->data, &req->hdrs)) != 0)) {
		return (rv);
	}
	return (0);
}

int
nni_http_res_copy_data(nni_http_res *res, const void *data, size_t size)
{
	int rv;

	if (((rv = http_entity_copy_data(&res->data, data, size)) != 0) ||
	    ((rv = http_set_content_length(&res->data, &res->hdrs)) != 0)) {
		return (rv);
	}
	return (0);
}

static int
http_parse_header(nni_list *hdrs, char *line)
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

	return (http_add_header(hdrs, key, val));
}

// http_sprintf_headers makes headers for an HTTP request or an HTTP response
// object.  Each header is dumped from the list. If the buf is NULL,
// or the sz is 0, then a dryrun is done, in order to allow the caller to
// determine how much space is needed. Returns the size of the space needed,
// not including the terminating NULL byte.  Truncation occurs if the size
// returned is >= the requested size.
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
http_asprintf(char **bufp, size_t *szp, nni_list *hdrs, const char *fmt, ...)
{
	va_list ap;
	size_t  len;
	size_t  n;
	char *  buf;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	len += http_sprintf_headers(NULL, 0, hdrs);
	len += 5; // \r\n\r\n\0

	if (len <= *szp) {
		buf = *bufp;
	} else {
		if ((buf = nni_alloc(len)) == NULL) {
			return (NNG_ENOMEM);
		}
		nni_free(*bufp, *szp);
		*bufp = buf;
		*szp  = len;
	}
	va_start(ap, fmt);
	n = vsnprintf(buf, len, fmt, ap);
	va_end(ap);
	buf += n;
	len -= n;
	n = http_sprintf_headers(buf, len, hdrs);
	buf += n;
	len -= n;
	snprintf(buf, len, "\r\n");
	return (0);
}

static int
http_req_prepare(nni_http_req *req)
{
	int rv;
	if ((req->uri == NULL) || (req->meth == NULL)) {
		return (NNG_EINVAL);
	}
	rv = http_asprintf(&req->buf, &req->bufsz, &req->hdrs, "%s %s %s\r\n",
	    req->meth, req->uri, req->vers != NULL ? req->vers : "HTTP/1.1");
	return (rv);
}

static int
http_res_prepare(nni_http_res *res)
{
	int rv;
	rv = http_asprintf(&res->buf, &res->bufsz, &res->hdrs, "%s %d %s\r\n",
	    res->vers != NULL ? res->vers : "HTTP/1.1", res->code,
	    res->rsn != NULL ? res->rsn : "Unknown Error");
	return (rv);
}

int
nni_http_req_get_buf(nni_http_req *req, void **data, size_t *szp)
{
	int rv;

	if ((req->buf == NULL) && (rv = http_req_prepare(req)) != 0) {
		return (rv);
	}
	*data = req->buf;
	*szp  = strlen(req->buf);
	return (0);
}

int
nni_http_res_get_buf(nni_http_res *res, void **data, size_t *szp)
{
	int rv;

	if ((res->buf == NULL) && (rv = http_res_prepare(res)) != 0) {
		return (rv);
	}
	*data = res->buf;
	*szp  = strlen(res->buf);
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

int
nni_http_req_init(nni_http_req **reqp)
{
	nni_http_req *req;
	if ((req = NNI_ALLOC_STRUCT(req)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&req->hdrs, http_header, node);
	req->buf       = NULL;
	req->bufsz     = 0;
	req->data.data = NULL;
	req->data.size = 0;
	req->data.own  = false;
	req->vers      = NULL;
	req->meth      = NULL;
	req->uri       = NULL;
	*reqp          = req;
	return (0);
}

int
nni_http_res_init(nni_http_res **resp)
{
	nni_http_res *res;
	if ((res = NNI_ALLOC_STRUCT(res)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&res->hdrs, http_header, node);
	res->buf       = NULL;
	res->bufsz     = 0;
	res->data.data = NULL;
	res->data.size = 0;
	res->data.own  = false;
	res->vers      = NULL;
	res->rsn       = NULL;
	res->code      = 0;
	*resp          = res;
	return (0);
}

const char *
nni_http_req_get_method(nni_http_req *req)
{
	return (req->meth);
}

const char *
nni_http_req_get_uri(nni_http_req *req)
{
	return (req->uri);
}

const char *
nni_http_req_get_version(nni_http_req *req)
{
	return (req->vers);
}

const char *
nni_http_res_get_version(nni_http_res *res)
{
	return (res->vers);
}

int
nni_http_req_set_version(nni_http_req *req, const char *vers)
{
	return (http_set_string(&req->vers, vers));
}

int
nni_http_res_set_version(nni_http_res *res, const char *vers)
{
	return (http_set_string(&res->vers, vers));
}

int
nni_http_req_set_uri(nni_http_req *req, const char *uri)
{
	return (http_set_string(&req->uri, uri));
}

int
nni_http_req_set_method(nni_http_req *req, const char *meth)
{
	return (http_set_string(&req->meth, meth));
}

int
nni_http_res_set_status(nni_http_res *res, int status, const char *reason)
{
	int rv;
	if ((rv = http_set_string(&res->rsn, reason)) != 0) {
		res->code = status;
	}
	return (rv);
}

int
nni_http_res_get_status(nni_http_res *res)
{
	return (res->code);
}

const char *
nni_http_res_get_reason(nni_http_res *res)
{
	return (res->rsn);
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
			*lenp        = len + 1;
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

static int
http_entity_parse(http_entity *entity, char *buf, size_t n, size_t *lenp)
{
	size_t cnt = 0;
	int    rv  = 0;
	if (entity->size) {
		cnt = entity->size - entity->len;
		if (cnt > n) { // We need more than is available.
			cnt = n;
			rv  = NNG_EAGAIN;
		}
		memcpy(entity->data + entity->len, buf, cnt);
		entity->len += cnt;
	}
	*lenp = cnt;
	return (rv);
}

static int
http_req_parse_line(nni_http_req *req, char *line)
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

int
http_req_parse(nni_http_req *req, char *buf, size_t n, size_t *lenp, bool dat)
{

	size_t len = 0;
	size_t cnt;
	char * line;
	int    rv = 0;
	for (;;) {
		if (req->data.size) {
			rv = http_entity_parse(&req->data, buf, n, &cnt);
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
		// for data, if the caller asked us to, and it's an HTTP/1.1
		// request.
		if (*line == '\0') {
			const char *cls;
			int         clen;
			if ((!dat) || (strcmp(req->vers, "HTTP/1.1") != 0)) {
				break;
			}
			cls = http_get_header(&req->hdrs, "Content-Length");
			if ((cls == NULL) || ((clen = atoi(cls)) < 1)) {
				break;
			}
			if ((req->data.data = nni_alloc(clen)) == NULL) {
				rv = NNG_ENOMEM;
				break;
			}
			req->data.size = (size_t) clen;
			req->data.len  = 0;
			req->data.own  = true;
			continue;
		}

		if (req->vers != NULL) {
			rv = http_parse_header(&req->hdrs, line);
		} else {
			rv = http_req_parse_line(req, line);
		}

		if (rv != 0) {
			break;
		}
	}

	*lenp = len;
	return (rv);
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
		// for data, if the caller asked us to, and it's an HTTP/1.1
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
			msg->datasz   = (size_t) clen;
			msg->datawidx = 0;
			msg->freedata = true;
			continue;
		}

		if (msg->vers != NULL) {
			rv = http_parse_header(&msg->hdrs, line);
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
	return (http_msg_parse(msg, buf, n, lenp, true));
}

// OBSOLETE HERE

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

const char *
nni_http_msg_get_version(nni_http_msg *msg)
{
	return (msg->vers);
}

void
nni_http_msg_reset(nni_http_msg *msg)
{
	http_header *h;

	msg->code = 0;
	nni_strfree(msg->meth);
	msg->meth = NULL;
	nni_strfree(msg->vers);
	msg->vers = NULL;
	nni_strfree(msg->uri);
	msg->uri = NULL;
	nni_strfree(msg->rsn);
	msg->rsn = NULL;
	if (msg->freedata && msg->datasz) {
		nni_free(msg->data, msg->datasz);
	}
	msg->data     = NULL;
	msg->datasz   = 0;
	msg->freedata = false;
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
}

int
xnni_http_msg_add_header(nni_http_msg *msg, const char *key, const char *val)
{
	return (http_add_header(&msg->hdrs, key, val));
}

int
nni_http_msg_set_header(nni_http_msg *msg, const char *key, const char *val)
{
	return (http_set_header(&msg->hdrs, key, val));
}

const char *
nni_http_msg_get_header(nni_http_msg *msg, const char *key)
{
	return (http_get_header(&msg->hdrs, key));
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
nni_http_msg_init_res(nni_http_msg **msgp)
{
	return (http_msg_init(msgp, HTTP_MSG_RESPONSE));
}

static int
http_msg_set_data(nni_http_msg *msg, const void *data, size_t sz)
{
	int  rv;
	char buf[16];
	(void) snprintf(buf, sizeof(buf), "%u", (unsigned) sz);

	if ((rv = nni_http_msg_set_header(msg, "Content-Length", buf)) != 0) {
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
nni_http_msg_set_data(nni_http_msg *msg, const void *data, size_t sz)
{
	return (http_msg_set_data(msg, data, sz));
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

static int
http_msg_prepare(nni_http_msg *m)
{
	size_t n, len;
	char * buf;
	char * vers;

	if ((vers = m->vers) == NULL) {
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

	if (len <= m->bufsz) {
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
	*szp  = strlen(msg->buf);
	return (0);
}
void
nni_http_msg_fini(nni_http_msg *msg)
{
	http_header *h;

	nni_http_msg_reset(msg);
	if (msg->bufsz) {
		nni_free(msg->buf, msg->bufsz);
	}
	NNI_FREE_STRUCT(msg);
}