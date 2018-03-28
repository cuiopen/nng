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
} rep_state;

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
		break;
	}
}

#define NCTX 100

TestMain("REQ concurrent contexts", {
	int         rv;
	const char *addr = "inproc://test";
	nng_ctx     ctxs[NCTX];
	uint32_t    send_order[NCTX];
	uint32_t    recv_order[NCTX];
	nng_aio *   aios[NCTX];
	int         i;

	memset(send_order, 0, NCTX * sizeof(int));
	memset(recv_order, 0, NCTX * sizeof(int));

	Convey("We can use REQ contexts concurrently", {
		nng_socket req;

		So(nng_aio_alloc(&rep_state.aio, (void *) rep_cb, NULL) == 0);
		So(nng_rep_open(&rep_state.s) == 0);
		So(nng_req_open(&req) == 0);

		// This is a very inefficient shuffle -- it's probably
		// O(n*log2(n)), but NCTX is small enough that we don't care.
		for (i = 0; i < NCTX; i++) {
			int si = rand() % NCTX; // recv index
			int ri = rand() % NCTX; // send index

			nng_aio_alloc(&aios[i], NULL, NULL);

			while (send_order[si] != 0) {
				si++;
				si %= NCTX;
			}
			send_order[si] = (uint32_t) i;
			while (recv_order[ri] != 0) {
				ri++;
				ri %= NCTX;
			}
			recv_order[ri] = (uint32_t) i;
		}
		Reset({
			for (i = 0; i < NCTX; i++) {
				nng_ctx_close(ctxs[i]);
			}
			nng_close(req);
			nng_close(rep_state.s);
			nng_aio_free(rep_state.aio);
		});

		So(nng_listen(rep_state.s, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

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
			nng_msg *msg;
			uint32_t si = send_order[i];
			if ((rv = nng_msg_alloc(&msg, sizeof(uint32_t))) !=
			    0) {
				Fail("msg alloc failed: %s", nng_strerror(rv));
			}
			if ((rv = nng_msg_append_u32(msg, si)) != 0) {
				Fail("append failed: %s", nng_strerror(rv));
			}
			nng_aio_set_msg(aios[si], msg);
			nng_ctx_send(ctxs[si], aios[si]);
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
				Fail("recv failed: %s", nng_strerror(rv));
				break;
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

	nng_fini();
});
