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

// Basic HTTP server tests.
#include "core/nng_impl.h"
#include "supplemental/http/http.h"
#include "supplemental/sha1/sha1.h"

const uint8_t utf8_sha1sum[20] = { 0x54, 0xf3, 0xb8, 0xbb, 0xfe, 0xda, 0x6f,
	0xb4, 0x96, 0xdd, 0xc9, 0x8b, 0x8c, 0x41, 0xf4, 0xfe, 0xe5, 0xa9, 0x7d,
	0xa9 };

TestMain("HTTP Client", {

	nni_http_server *s;

	nni_init();
	atexit(nng_fini);

	Convey("We can start a TCP server", {
		nng_sockaddr sa;
		nni_aio *    aio;
		char         portbuf[16];
		char *doc = "<html><body>Someone <b>is</b> home!</body</html>";

		trantest_next_address(portbuf, "%u");

		So(nni_aio_init(&aio, NULL, NULL) == 0);
		aio->a_addr = &sa;
		nni_plat_tcp_resolv("127.0.0.1", portbuf, NNG_AF_INET, 0, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);

		So(nni_http_server_init(&s) == 0);
		Reset({ nni_http_server_fini(s); });
		So(nni_http_server_add_static(s, NULL, "text/html",
		       "/home.html", doc, strlen(doc)) == 0);
		So(nni_http_server_start(s, &sa) == 0);

		printf("TIMEOUT HERE DURING DEVELOPMENT EXPECTED!\n");
		nng_msleep(10000000);
	});
#if 0
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
			nni_http_req *req;
			nni_http_res *res;
			nni_http_tran t;

			t.h_data  = p;
			t.h_write = (void *) nni_plat_tcp_pipe_send;
			t.h_read  = (void *) nni_plat_tcp_pipe_recv;
			t.h_close = (void *) nni_plat_tcp_pipe_close;

			So(nni_http_init(&http, &t) == 0);
			So(http != NULL);

			So(nni_http_req_init(&req) == 0);
			So(nni_http_res_init(&res) == 0);
			Reset({
				nni_http_close(http);
				nni_http_req_fini(req);
				nni_http_res_fini(res);
			});
			So(nni_http_req_set_method(req, "GET") == 0);
			So(nni_http_req_set_version(req, "HTTP/1.1") == 0);
			So(nni_http_req_set_uri(req, "/encoding/utf8") == 0);
			So(nni_http_req_set_header(
			       req, "Host", "httpbin.org") == 0);
			nni_http_write_req(http, req, iaio);

			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nni_http_read_res(http, res, iaio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nni_http_res_get_status(res) == 200);

			Convey("The message contents are  correct", {
				uint8_t     digest[20];
				void *      data;
				const char *cstr;
				size_t      sz;

				cstr = nni_http_res_get_header(
				    res, "Content-Length");
				So(cstr != NULL);
				sz = atoi(cstr);
				So(sz > 0);

				data = nni_alloc(sz);
				So(data != NULL);
				Reset({ nni_free(data, sz); });

				iaio->a_niov           = 1;
				iaio->a_iov[0].iov_len = sz;
				iaio->a_iov[0].iov_buf = data;

				nni_aio_wait(iaio);
				So(nng_aio_result(aio) == 0);

				nni_http_read_full(http, iaio);
				nni_aio_wait(iaio);
				So(nni_aio_result(iaio) == 0);

				nni_sha1(data, sz, digest);
				So(memcmp(digest, utf8_sha1sum, 20) == 0);
			});
		});
	});
#endif
});
