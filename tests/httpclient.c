//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

// Basic HTTP client tests.
#include "core/nng_impl.h"
#include "supplemental/http/http.h"

TestMain("HTTP Client", {

	nni_init();
	atexit(nng_fini);

	Convey("Given a TCP connection to httpbin.org", {
		nni_plat_tcp_ep *  ep;
		nni_plat_tcp_pipe *p;
		nng_aio *          aio;
		nni_aio *          iaio;
		nng_sockaddr       rsa;
		nng_sockaddr       lsa;

		lsa.s_un.s_family = NNG_AF_UNSPEC;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		iaio         = (nni_aio *) aio;
		iaio->a_addr = &rsa;

		nng_aio_set_timeout(aio, nni_clock() + 10000);
		nni_plat_tcp_resolv("httpbin.org", "80", NNG_AF_INET, 0, iaio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		So(rsa.s_un.s_in.sa_port == htons(80));

		So(nni_plat_tcp_ep_init(&ep, &lsa, &rsa, NNI_EP_MODE_DIAL) ==
		    0);
		nni_plat_tcp_ep_connect(ep, iaio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		p = nni_aio_get_pipe(iaio);
		So(p != NULL);
		Reset({
			nni_plat_tcp_ep_fini(ep);
			nni_plat_tcp_pipe_fini(p);
		});
		Convey("We can initiate a message", {
			nni_http *    http;
			nni_http_msg *req;
			nni_http_msg *res;
			nni_http_tran t;

			t.h_data  = p;
			t.h_write = (void *) nni_plat_tcp_pipe_send;
			t.h_read  = (void *) nni_plat_tcp_pipe_recv;
			t.h_close = (void *) nni_plat_tcp_pipe_close;

			So(nni_http_init(&http, &t) == 0);
			So(http != NULL);

			So(nni_http_msg_init_req(&req) == 0);
			So(nni_http_msg_init_res(&res) == 0);
			Reset({
				nni_http_close(http);
				nni_http_msg_fini(req);
				nni_http_msg_fini(res);
			});
			So(nni_http_msg_set_method(req, "GET") == 0);
			So(nni_http_msg_set_version(req, "HTTP/1.1") == 0);
			So(nni_http_msg_set_uri(req, "/get") == 0);
			So(nni_http_msg_set_header(
			       req, "Host", "httpbin.org") == 0);
			nni_http_write_msg(http, req, iaio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nni_http_read_msg(http, res, iaio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nni_http_msg_get_status(res) == 200);
		});
	});
});
