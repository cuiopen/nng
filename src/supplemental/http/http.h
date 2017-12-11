//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_H

#include <stdbool.h>

// nni_http_msg represents an HTTP request or response message.
typedef struct nni_http_msg    nni_http_msg;
typedef struct nni_http_res    nni_http_res;
typedef struct nni_http_entity nni_http_entity;

typedef struct nni_http_tran {
	void *h_data;
	void (*h_read)(void *, nni_aio *);
	void (*h_write)(void *, nni_aio *);
	void (*h_close)(void *);
} nni_http_tran;

typedef struct nni_http_req nni_http_req;

extern int  nni_http_req_init(nni_http_req **);
extern void nni_http_req_fini(nni_http_req *);
extern void nni_http_req_reset(nni_http_req *);
extern int nni_http_req_set_header(nni_http_req *, const char *, const char *);
extern int nni_http_req_add_header(nni_http_req *, const char *, const char *);
extern int nni_http_req_del_header(nni_http_req *, const char *);
extern int nni_http_req_get_buf(nni_http_req *, void **, size_t *);
extern int nni_http_req_set_method(nni_http_req *, const char *);
extern int nni_http_req_set_version(nni_http_req *, const char *);
extern int nni_http_req_set_uri(nni_http_req *, const char *);
extern const char *nni_http_req_get_header(nni_http_req *, const char *);
extern const char *nni_http_req_get_header(nni_http_req *, const char *);
extern const char *nni_http_req_get_version(nni_http_req *);
extern const char *nni_http_req_get_uri(nni_http_req *);
extern int nni_http_req_parse(nni_http_req *, void *, size_t, size_t *);

extern int  nni_http_res_init(nni_http_res **);
extern void nni_http_res_fini(nni_http_res *);
extern void nni_http_res_reset(nni_http_res *);
extern int  nni_http_res_get_buf(nni_http_res *, void **, size_t *);
extern int nni_http_res_set_header(nni_http_res *, const char *, const char *);
extern int nni_http_res_add_header(nni_http_res *, const char *, const char *);
extern int nni_http_res_del_header(nni_http_res *, const char *);
extern const char *nni_http_res_get_header(nni_http_res *, const char *);
extern const char *nni_http_res_get_version(nni_http_res *);
extern const char *nni_http_res_get_reason(nni_http_res *);
extern int         nni_http_res_get_status(nni_http_res *);
extern int  nni_http_res_parse(nni_http_res *, void *, size_t, size_t *);
extern int  nni_http_res_set_data(nni_http_res *, const void *, size_t);
extern int  nni_http_res_copy_data(nni_http_res *, const void *, size_t);
extern int  nni_http_res_alloc_data(nni_http_res *, size_t);
extern void nni_http_res_get_data(nni_http_res *, void **, size_t *);

// HTTP status codes.  This list is not exhaustive.
enum { NNI_HTTP_STATUS_CONTINUE                  = 100,
	NNI_HTTP_STATUS_SWITCHING                = 101,
	NNI_HTTP_STATUS_PROCESSING               = 102,
	NNI_HTTP_STATUS_OK                       = 200,
	NNI_HTTP_STATUS_CREATED                  = 201,
	NNI_HTTP_STATUS_ACCEPTED                 = 202,
	NNI_HTTP_STATUS_NOT_AUTHORITATIVE        = 203,
	NNI_HTTP_STATUS_NO_CONTENT               = 204,
	NNI_HTTP_STATUS_RESET_CONTENT            = 205,
	NNI_HTTP_STATUS_PARTIAL_CONTENT          = 206,
	NNI_HTTP_STATUS_MULTI_STATUS             = 207,
	NNI_HTTP_STATUS_ALREADY_REPORTED         = 208,
	NNI_HTTP_STATUS_IM_USED                  = 226,
	NNI_HTTP_STATUS_MULTIPLE_CHOICES         = 300,
	NNI_HTTP_STATUS_STATUS_MOVED_PERMANENTLY = 301,
	NNI_HTTP_STATUS_FOUND                    = 302,
	NNI_HTTP_STATUS_SEE_OTHER                = 303,
	NNI_HTTP_STATUS_NOT_MODIFIED             = 304,
	NNI_HTTP_STATUS_USE_PROXY                = 305,
	NNI_HTTP_STATUS_TEMPORARY_REDIRECT       = 307,
	NNI_HTTP_STATUS_PERMANENT_REDIRECT       = 308,
	NNI_HTTP_STATUS_BAD_REQUEST              = 400,
	NNI_HTTP_STATUS_UNAUTHORIZED             = 401,
	NNI_HTTP_STATUS_PAYMENT_REQUIRED         = 402,
	NNI_HTTP_STATUS_FORBIDDEN                = 403,
	NNI_HTTP_STATUS_NOT_FOUND                = 404,
	NNI_HTTP_STATUS_METHOD_NOT_ALLOWED       = 405,
	NNI_HTTP_STATUS_NOT_ACCEPTABLE           = 406,
	NNI_HTTP_STATUS_PROXY_AUTH_REQUIRED      = 407,
	NNI_HTTP_STATUS_REQUEST_TIMEOUT          = 408,
	NNI_HTTP_STATUS_CONFLICT                 = 409,
	NNI_HTTP_STATUS_GONE                     = 410,
	NNI_HTTP_STATUS_LENGTH_REQUIRED          = 411,
	NNI_HTTP_STATUS_PRECONDITION_FAILED      = 412,
	NNI_HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
	NNI_HTTP_STATUS_REQUEST_URI_TOO_LONG     = 414,
	NNI_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE   = 415,
	NNI_HTTP_STATUS_RANGE_NOT_SATISFIABLE    = 416,
	NNI_HTTP_STATUS_EXPECTATION_FAILED       = 417,
	NNI_HTTP_STATUS_TEAPOT                   = 418,
	NNI_HTTP_STATUS_UNPROCESSABLE_ENTITY     = 422,
	NNI_HTTP_STATUS_LOCKED                   = 423,
	NNI_HTTP_STATUS_FAILED_DEPENDENCY        = 424,
	NNI_HTTP_STATUS_UPGRADE_REQUIRED         = 426,
	NNI_HTTP_STATUS_PRECONDITION_REQUIRED    = 428,
	NNI_HTTP_STATUS_TOO_MANY_REQUESTS        = 429,
	NNI_HTTP_STATUS_HEADERS_TOO_LARGE        = 431,
	NNI_HTTP_STATUS_UNAVAIL_LEGAL_REASONS    = 451,
	NNI_HTTP_STATUS_INTERNAL_SERVER_ERROR    = 500,
	NNI_HTTP_STATUS_NOT_IMPLEMENTED          = 501,
	NNI_HTTP_STATUS_BAD_GATEWAY              = 502,
	NNI_HTTP_STATUS_SERVICE_UNAVAILABLE      = 503,
	NNI_HTTP_STATUS_GATEWAY_TIMEOUT          = 504,
	NNI_HTTP_STATUS_HTTP_VERSION_NOT_SUPP    = 505,
	NNI_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES  = 506,
	NNI_HTTP_STATUS_INSUFFICIENT_STORAGE     = 507,
	NNI_HTTP_STATUS_LOOP_DETECTED            = 508,
	NNI_HTTP_STATUS_NOT_EXTENDED             = 510,
	NNI_HTTP_STATUS_NETWORK_AUTH_REQUIRED    = 511,
};

// An HTTP connection is a connection over which messages are exchanged.
// Generally, clients send request messages, and then read responses.
// Servers, read requests, and write responses.  However, we do not
// require a 1:1 mapping between request and response here -- the application
// is responsible for dealing with that.
//
// We only support HTTP/1.1, though using the nni_http_conn_read and
// nni_http_conn_write low level methods, it is possible to write an upgrader
// (such as websocket!) that might support e.g. HTTP/2 or reading data that
// follows a legacy HTTP/1.0 message.
//
// Any error on the connection, including cancellation of a request, is fatal
// the connection.
typedef struct nni_http nni_http;

extern int  nni_http_init(nni_http **, nni_http_tran *);
extern void nni_http_close(nni_http *);
extern void nni_http_fini(nni_http *);

// Reading messages -- the caller must supply a preinitialized (but otherwise
// idle) message.  We recommend the caller store this in the aio's user data.
// Note that the iovs of the aio's are clobbered by these methods -- callers
// must not use them for any other purpose.

extern void nni_http_write_req(nni_http *, nni_http_req *, nni_aio *);
extern void nni_http_write_res(nni_http *, nni_http_res *, nni_aio *);
extern void nni_http_read_req(nni_http *, nni_http_req *, nni_aio *);
extern void nni_http_read_res(nni_http *, nni_http_res *, nni_aio *);

extern void nni_http_read(nni_http *, nni_aio *);
extern void nni_http_read_full(nni_http *, nni_aio *);
extern void nni_http_write(nni_http *, nni_aio *);
extern void nni_http_write_full(nni_http *, nni_aio *);

// An HTTP client works like an HTTP channel, but it has the logic to
// establish the connection, etc.  At present no connection caching is
// used, but that can change in the future.
typedef struct nni_http_client nni_http_client;

extern int nni_http_client_init(nni_http_client *, const char *);

typedef struct nni_http_server nni_http_server;

typedef struct {
	// h_path is the relative URI that we are going to match against.
	// Must not be NULL.  Note that query parameters (things following
	// a "?" at the end of the path) are ignored when matching.  This
	// field may not be NULL.
	const char *h_path;

	// h_method is the HTTP method to handle such as "GET" or "POST".
	// Must not be empty or NULL.  If the incoming method is HEAD, then
	// the server will process HEAD the same as GET, but will not send
	// any response body.
	const char *h_method;

	// h_host is used to match on a specific Host: entry.  If left NULL,
	// then this handler will match regardless of the Host: value.
	const char *h_host;

	// h_is_dir indicates that the path represents a directory, and
	// any path which is a logically below it should also be matched.
	// This means that "/phone" will match for "/phone/bob" but not
	// "/phoneme/ma".  Be advised that it is not possible to register
	// a handler for a parent and a different handler for children.
	// (This restriction may be lifted in the future.)
	bool h_is_dir;

	// h_cb is a callback that handles the request.  The conventions
	// are as follows:
	//
	// inputs:
	//   0 - nni_http * for the actual underlying HTTP channel
	//   1 - nni_http_msg * for the HTTP request object
	//   2 - void * for the opaque pointer supplied at registration
	//
	// outputs:
	//   0 - (optional) nni_http * for an HTTP response (see below)
	//
	// The callback may choose to return the a response object in output 0,
	// in which case the framework will handle sending the reply.
	// (Response entity content is also sent if the response data
	// is not NULL.)  The callback may instead do it's own replies, in
	// which case the response output should be NULL.
	//
	// Note that any request entity data is *NOT* supplied automatically
	// with the request object; the callback is expected to call the
	// nni_http_read_data method to retrieve any message data based upon
	// the presence of headers. (It may also call nni_http_read or
	// nni_http_write on the channel as it sees fit.)
	//
	// An "upgrader" that wants to take over complete ownership of the
	// channel should not call the completion callback until the
	// channel is closed.  Note that timeouts on replies are automatically
	// disabled.  (An example of an "upgrader" would be a websocket
	// implementation.)
	void (*h_cb)(nni_aio *);
} nni_http_handler;

extern int nni_http_server_init(nni_http_server **);

// nni_http_server_fini closes down the server, and frees all resources
// associated with it.  It does not affect any upgraded connections.
extern void nni_http_server_fini(nni_http_server *);

// nni_http_server_add_handler registers a new handler on the server.
// This function will return NNG_EADDRINUSE if a conflicting handler
// is already registered (i.e. a handler with the same value for Host,
// Method, and URL.)  The first parameter receives an opaque handle to
// the handler, that can be used to unregister the handler later.
extern int nni_http_server_add_handler(
    void **, nni_http_server *, nni_http_handler *, void *);

extern void nni_http_server_del_handler(nni_http_server *, void *);

// The server has its own handlers for certain error conditions.  You can
// override the handlers for those using the following.  Most commonly this
// will be to supply a custom 404 page.  Note that unlike a normal handler,
// it is not possible to override the status code.  Not every error code
// will be handleable, but many of the 4xx codes are, including especially
// 404 and 405.  The callback function has the same semantics as the
// h_cb member of nni_http_handler.
extern int nni_http_server_set_error_handler(
    nni_http_server *, int, void (*)(nni_aio *), void *);

// nni_http_server_start starts listening on the supplied port.
extern int nni_http_server_start(nni_http_server *, nng_sockaddr *);

// nni_http_server_stop stops the server, closing the listening socket.
// Connections that have been "upgraded" are unaffected.  Connections
// associated with a callback will complete their callback, and then close.
extern void nni_http_server_stop(nni_http_server *);

// TLS will use
// extern int nni_http_server_start_tls(nni_http_server *, nng_sockaddr *,
//     nni_tls_config *);

#endif // NNG_SUPPLEMENTAL_HTTP_HTTP_H
