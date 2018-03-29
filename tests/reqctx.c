//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "protocol/reqrep0/rep.h"
#include "protocol/reqrep0/req.h"
#include "stubs.h"
#include "supplemental/util/platform.h"

#include <string.h>

static struct {
	nng_aio *aio;
	enum { START, SEND, RECV } state;
	nng_socket s;
	nng_msg *  msg;
	int        cnt;
} rep_state;

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>

#include <mswsock.h>
bool
isready(int fd)
{
	WSAPOLLFD pfd;
	pfd.fd      = (SOCKET) fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (WSAPoll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	default:
		printf("BAD POLL RETURN!\n");
		abort();
	}
}
#else
#include <poll.h>
bool
isready(int fd)
{
	struct pollfd pfd;
	pfd.fd      = fd;
	pfd.events  = POLLIN;
	pfd.revents = 0;
	switch (poll(&pfd, 1, 0)) {
	case 0:
		return (0);
	case 1:
		return (1);
	default:
		printf("BAD POLL RETURN!\n");
		abort();
	}
}
#endif

void
rep_cb(void)
{
	int rv;

	if (rep_state.state == START) {
		rep_state.state = RECV;
		nng_recv_aio(rep_state.s, rep_state.aio);
		return;
	}
	if ((rv = nng_aio_result(rep_state.aio)) != 0) {
		if (rep_state.msg != NULL) {
			nng_msg_free(rep_state.msg);
			rep_state.msg = NULL;
		}
		return;
	}
	switch (rep_state.state) {
	case START:
		break;
	case RECV:
		rep_state.msg   = nng_aio_get_msg(rep_state.aio);
		rep_state.state = SEND;
		nng_aio_set_msg(rep_state.aio, rep_state.msg);
		nng_send_aio(rep_state.s, rep_state.aio);
		break;
	case SEND:
		rep_state.msg   = NULL;
		rep_state.state = RECV;
		nng_aio_set_msg(rep_state.aio, NULL);
		nng_recv_aio(rep_state.s, rep_state.aio);
		rep_state.cnt++;
		break;
	}
}

#define NCTX 1000

TestMain("REQ concurrent contexts", {
	int         rv;
	const char *addr = "inproc://test";
	nng_ctx     ctxs[NCTX];
	uint32_t    recv_order[NCTX];
	nng_aio *   aios[NCTX];
	int         i;

	memset(recv_order, 0, NCTX * sizeof(int));

	Convey("We can use REQ contexts concurrently", {
		nng_socket req;

		So(nng_aio_alloc(&rep_state.aio, (void *) rep_cb, NULL) == 0);
		So(nng_rep_open(&rep_state.s) == 0);
		So(nng_req_open(&req) == 0);

		for (i = 0; i < NCTX; i++) {
			recv_order[i] = (uint32_t) i;
			if (nng_aio_alloc(&aios[i], NULL, NULL) != 0) {
				break;
			}
			nng_aio_set_timeout(aios[i], 5000);
		}
		So(i == NCTX);
		for (i = 0; i < NCTX; i++) {
			uint32_t tmp;
			int      ni = rand() % NCTX; // recv index

			tmp            = recv_order[i];
			recv_order[i]  = recv_order[ni];
			recv_order[ni] = tmp;
		}
		Reset({
			for (i = 0; i < NCTX; i++) {
				nng_ctx_close(ctxs[i]);
				nng_aio_free(aios[i]);
			}
			nng_close(req);
			nng_close(rep_state.s);
			nng_aio_free(rep_state.aio);
		});

		So(nng_listen(rep_state.s, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

		nng_msleep(100); // let things establish.

		// Start the rep state machine going.
		rep_cb();

		for (i = 0; i < NCTX; i++) {
			if ((rv = nng_ctx_open(&ctxs[i], req)) != 0) {
				break;
			}
		}
		So(rv == 0);
		So(i == NCTX);

		// Send messages
		for (i = 0; i < NCTX; i++) {
			nng_msg *m;
			if ((rv = nng_msg_alloc(&m, sizeof(uint32_t))) != 0) {
				Fail("msg alloc failed: %s", nng_strerror(rv));
			}
			if ((rv = nng_msg_append_u32(m, i)) != 0) {
				Fail("append failed: %s", nng_strerror(rv));
			}
			nng_aio_set_msg(aios[i], m);
			nng_ctx_send(ctxs[i], aios[i]);
		}
		So(rv == 0);
		So(i == NCTX);

		for (i = 0; i < NCTX; i++) {
			nng_aio_wait(aios[i]);
			if ((rv = nng_aio_result(aios[i])) != 0) {
				Fail("send failed: %s", nng_strerror(rv));
				So(false);
				break;
			}
		}
		So(rv == 0);
		So(i == NCTX);
		// Receive answers
		for (i = 0; i < NCTX; i++) {
			int ri = recv_order[i];
			nng_ctx_recv(ctxs[ri], aios[ri]);
		}

		for (i = 0; i < NCTX; i++) {
			nng_msg *msg;
			uint32_t x;

			nng_aio_wait(aios[i]);
			if ((rv = nng_aio_result(aios[i])) != 0) {
				Fail("recv %d (%d) %d failed: %s", i,
				    recv_order[i], rep_state.cnt,
				    nng_strerror(rv));
				nng_ctx_close(ctxs[i]);
				continue;
			}
			msg = nng_aio_get_msg(aios[i]);
			if ((rv = nng_msg_chop_u32(msg, &x)) != 0) {
				Fail("recv msg trim: %s", nng_strerror(rv));
				break;
			}
			if (x != (uint32_t) i) {
				Fail("message body mismatch: %x %x\n", x,
				    (uint32_t) i);
				break;
			}
			nng_ctx_close(ctxs[i]);
		}
		So(rv == 0);
		So(i == NCTX);
	});

	Convey("Pollable status REQ contexts work", {
		nng_socket req;
		nng_socket rep;
		nng_ctx    ctx;

		So(nng_req0_open(&req) == 0);
		So(nng_rep0_open(&rep) == 0);
		So(nng_ctx_open(&ctx, req) == 0);

		Reset({
			nng_ctx_close(ctx);
			nng_close(req);
			nng_close(rep);
		});

		So(nng_listen(rep, "inproc://ctx1", NULL, 0) == 0);
		So(nng_dial(req, "inproc://ctx1", NULL, 0) == 0);

		Convey("REQ context always writable", {
			int fd1;
			int fd2;

			So(nng_getopt_int(req, NNG_OPT_SENDFD, &fd1) == 0);
			So(isready(fd1) == true);

			So(nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd2) == 0);
			So(fd2 != fd1);
			So(isready(fd2) == true);
		});

		Convey("REQ context starts not readable", {
			int fd1;
			int fd2;

			So(nng_getopt_int(req, NNG_OPT_RECVFD, &fd1) == 0);
			So(isready(fd1) == false);

			So(nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd2) == 0);
			So(fd2 != fd1);
			So(isready(fd2) == false);
		});

		Convey("REQ context becomes readable", {
			int      fd1;
			int      fd2;
			nng_aio *aio;
			nng_msg *msg;

			So(nng_aio_alloc(&aio, NULL, NULL) == 0);
			So(nng_msg_alloc(&msg, 0) == 0);
			Reset({ nng_aio_free(aio); });
			nng_aio_set_timeout(aio, 100); // 100 ms max
			So(nng_getopt_int(req, NNG_OPT_RECVFD, &fd1) == 0);
			So(nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd2) == 0);
			So(fd2 != fd1);
			So(isready(fd2) == false);
			So(isready(fd1) == false);
			So(nng_msg_append(msg, "xyz", 3) == 0);
			nng_aio_set_msg(aio, msg);
			nng_ctx_send(ctx, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_recvmsg(rep, &msg, 0) == 0); // recv on rep
			So(nng_sendmsg(rep, msg, 0) == 0);  // echo it back
			nng_msleep(20); // give time for message to arrive
			So(isready(fd1) == false);
			So(isready(fd2) == true);
			nng_ctx_recv(ctx, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nng_msg_free(nng_aio_get_msg(aio));
			So(isready(fd2) == false); // no longer receivable
		});
	});

	nng_fini();
});
