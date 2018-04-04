//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "protocol/reqrep0/req.h"

// Request protocol.  The REQ protocol is the "request" side of a
// request-reply pair.  This is useful for building RPC clients, for example.

#ifndef NNI_PROTO_REQ_V0
#define NNI_PROTO_REQ_V0 NNI_PROTO(3, 0)
#endif

#ifndef NNI_PROTO_REP_V0
#define NNI_PROTO_REP_V0 NNI_PROTO(3, 1)
#endif

typedef struct req0_pipe req0_pipe;
typedef struct req0_sock req0_sock;
typedef struct req0_ctx  req0_ctx;

static void req0_run_sendq(req0_sock *);
static void req0_ctx_reset(req0_ctx *);
static void req0_ctx_timeout(void *);
static void req0_pipe_fini(void *);

// A req0_ctx is a "context" for the request.  It uses most of the
// socket, but keeps track of its own outstanding replays, the request ID,
// and so forth.
struct req0_ctx {
	nni_list_node  snode;
	nni_list_node  sqnode; // node on the sendq
	nni_list_node  pnode;  // node on the pipe list
	uint32_t       reqid;
	req0_sock *    sock;
	nni_aio *      aio;    // user aio waiting to receive - only one!
	nng_msg *      reqmsg; // request message
	nng_msg *      repmsg; // reply message
	nni_timer_node timer;
	nni_duration   retry;
	bool           notify; // if true, send notifications
	nni_pollable * recvable;
	nni_pollable * sendable;
};

// A req0_sock is our per-socket protocol private structure.
struct req0_sock {
	nni_msgq *   uwq;
	nni_msgq *   urq;
	nni_sock *   nsock;
	nni_duration retry;
	bool         raw;
	bool         wantw;
	bool         closed;
	int          ttl;

	req0_ctx sctx; // base socket ctx

	nni_list readypipes;
	nni_list busypipes;
	nni_list ctxs;

	nni_list    sendq;  // contexts waiting to send.
	nni_idhash *reqids; // contexts by request ID

	uint32_t nextid;   // next id
	uint8_t  reqid[4]; // outstanding request ID (big endian)
	nni_mtx  mtx;
	nni_cv   cv;
};

// A req0_pipe is our per-pipe protocol private structure.
struct req0_pipe {
	nni_pipe *    pipe;
	req0_sock *   req;
	nni_list_node node;
	nni_list      ctxs;           // ctxs with pending traffic
	nni_aio *     aio_getq;       // raw mode only
	nni_aio *     aio_sendraw;    // raw mode only
	nni_aio *     aio_sendcooked; // cooked mode only
	nni_aio *     aio_recv;
	nni_aio *     aio_putq;
	nni_mtx       mtx;
};

static void req0_sock_fini(void *);
static void req0_getq_cb(void *);
static void req0_sendraw_cb(void *);
static void req0_sendcooked_cb(void *);
static void req0_recv_cb(void *);
static void req0_putq_cb(void *);

static int
req0_sock_init_impl(void **sp, nni_sock *sock, bool raw)
{
	req0_sock *s;
	int        rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_idhash_init(&s->reqids)) != 0) {
		NNI_FREE_STRUCT(s);
		return (rv);
	}

	// Request IDs are 32 bits, with the high order bit set.
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_idhash_set_limits(
	    s->reqids, 0x80000000u, 0xffffffffu, nni_random() | 0x80000000u);

	nni_mtx_init(&s->mtx);
	nni_cv_init(&s->cv, &s->mtx);

	NNI_LIST_INIT(&s->readypipes, req0_pipe, node);
	NNI_LIST_INIT(&s->busypipes, req0_pipe, node);
	NNI_LIST_INIT(&s->sendq, req0_ctx, sqnode);
	NNI_LIST_INIT(&s->ctxs, req0_ctx, snode);

	// this is "semi random" start for request IDs.
	s->nsock = sock;

	nni_timer_init(&s->sctx.timer, req0_ctx_timeout, &s->sctx);
	s->sctx.sock   = s;
	s->sctx.notify = true;
	s->sctx.retry  = NNI_SECOND * 60;
	nni_list_append(&s->ctxs, &s->sctx);

	if (!raw) {
		if (((rv = nni_pollable_alloc(&s->sctx.sendable)) != 0) ||
		    ((rv = nni_pollable_alloc(&s->sctx.recvable)) != 0)) {
			req0_sock_fini(s);
			return (rv);
		}
		// Always sendable!
		nni_pollable_raise(s->sctx.sendable);
	}

	s->raw = raw;
	s->ttl = 8;
	s->uwq = nni_sock_sendq(sock);
	s->urq = nni_sock_recvq(sock);
	*sp    = s;

	return (0);
}

static int
req0_sock_init(void **sp, nni_sock *sock)
{
	return (req0_sock_init_impl(sp, sock, false));
}

static int
req0_sock_init_raw(void **sp, nni_sock *sock)
{
	return (req0_sock_init_impl(sp, sock, true));
}

static void
req0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
req0_sock_close(void *arg)
{
	req0_sock *s = arg;
	req0_ctx * ctx;

	nni_mtx_lock(&s->mtx);
	s->closed = true;
	NNI_LIST_FOREACH (&s->ctxs, ctx) {
		if (ctx->aio != NULL) {
			nni_aio_finish_error(ctx->aio, NNG_ECLOSED);
			ctx->aio = NULL;
			req0_ctx_reset(ctx);
		}
	}
	nni_mtx_unlock(&s->mtx);
	nni_timer_cancel(&s->sctx.timer);
}

static void
req0_sock_fini(void *arg)
{
	req0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	while ((!nni_list_empty(&s->readypipes)) ||
	    (!nni_list_empty(&s->busypipes))) {
		nni_cv_wait(&s->cv);
	}
	nni_idhash_fini(s->reqids);
	nni_timer_fini(&s->sctx.timer);
	nni_mtx_unlock(&s->mtx);

	nni_pollable_free(s->sctx.recvable);
	nni_pollable_free(s->sctx.sendable);

	nni_cv_fini(&s->cv);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static void
req0_pipe_fini(void *arg)
{
	req0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_sendcooked);
	nni_aio_fini(p->aio_sendraw);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
req0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	req0_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->aio_getq, req0_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, req0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, req0_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_sendraw, req0_sendraw_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_sendcooked, req0_sendcooked_cb, p)) !=
	        0)) {
		req0_pipe_fini(p);
		return (rv);
	}

	NNI_LIST_NODE_INIT(&p->node);
	NNI_LIST_INIT(&p->ctxs, req0_ctx, pnode);
	p->pipe = pipe;
	p->req  = s;
	*pp     = p;
	return (0);
}

static int
req0_pipe_start(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_REP_V0) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	if (s->closed) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_ECLOSED);
	}
	nni_list_append(&s->readypipes, p);
	req0_run_sendq(s);
	nni_mtx_unlock(&s->mtx);

	// Post a get on the upper write queue.  This is only used
	// in raw mode, but it also gets closed down when the socket
	// itself is shutdown.
	nni_msgq_aio_get(s->uwq, p->aio_getq);
	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
req0_pipe_stop(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;
	req0_ctx * ctx;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_sendcooked);
	nni_aio_stop(p->aio_sendraw);

	// At this point there should not be any further AIOs running.
	// Further, any completion tasks have completed.

	nni_mtx_lock(&s->mtx);
	// This removes the node from either busypipes or readypipes.
	// It doesn't much matter which.
	if (nni_list_node_active(&p->node)) {
		nni_list_node_remove(&p->node);
		if (s->closed) {
			nni_cv_wake(&s->cv);
		}
	}

	while ((ctx = nni_list_first(&p->ctxs)) != NULL) {
		nni_list_remove(&p->ctxs, ctx);
		// Reset the timer on this so it expires immediately.
		// This is actually easier than canceling the timer and
		// running the sendq separately.  (In particular, it avoids
		// a potential deadlock on cancelling the timer.)
		nni_timer_schedule(&ctx->timer, NNI_TIME_ZERO);
	}
	nni_mtx_unlock(&s->mtx);
}

// Raw and cooked mode differ in the way they send messages out.
//
// For cooked mode, we use a context, and send out that way.  This
// completely bypasses the upper write queue.  Each context keeps one
// message pending; these are "scheduled" via the sendq.  The sendq
// is ordered, so FIFO ordering between contexts is provided for.
//
// For raw mode we can just let the pipes "contend" via getq to get a
// message from the upper write queue.  The msgqueue implementation
// actually provides ordering, so load will be spread automatically.
// (NB: We may have to revise this in the future if we want to provide some
// kind of priority.)

static void
req0_getq_cb(void *arg)
{
	req0_pipe *p = arg;

	// We should be in RAW mode.  Cooked mode traffic bypasses
	// the upper write queue entirely, and should never end up here.
	// If the mode changes, we may briefly deliver a message, but
	// that's ok (there's an inherent race anyway).  (One minor
	// exception: we wind up here in error state when the uwq is closed.)

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_sendraw, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	// Send the message, but use the raw mode aio.
	nni_pipe_send(p->pipe, p->aio_sendraw);
}

static void
req0_sendraw_cb(void *arg)
{
	req0_pipe *p = arg;

	if (nni_aio_result(p->aio_sendraw) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_sendraw));
		nni_aio_set_msg(p->aio_sendraw, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	// Sent a message so we just need to look for another one.
	nni_msgq_aio_get(p->req->uwq, p->aio_getq);
}

static void
req0_sendcooked_cb(void *arg)
{
	req0_pipe *p = arg;
	req0_sock *s = p->req;

	if (nni_aio_result(p->aio_sendcooked) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(p->aio_sendcooked));
		nni_aio_set_msg(p->aio_sendcooked, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	// Cooked mode.  We completed a cooked send, so we need to
	// reinsert ourselves in the ready list, and re-run the sendq.

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->busypipes, p)) {
		nni_list_remove(&s->busypipes, p);
		nni_list_append(&s->readypipes, p);
		req0_run_sendq(s);
	} else {
		// We wind up here if stop was called from the reader
		// side while we were waiting to be scheduled to run for the
		// writer side.  In this case we can't complete the operation,
		// and we have to abort.
		nni_pipe_stop(p->pipe);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
req0_putq_cb(void *arg)
{
	req0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}
	nni_aio_set_msg(p->aio_putq, NULL);

	nni_pipe_recv(p->pipe, p->aio_recv);
}

static void
req0_recv_cb(void *arg)
{
	req0_pipe *p    = arg;
	req0_sock *sock = p->req;
	req0_ctx * ctx;
	nni_msg *  msg;
	nni_aio *  aio;
	uint32_t   id;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// We yank 4 bytes from front of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Malformed message.
		goto malformed;
	}
	id = nni_msg_trim_u32(msg);
	if (nni_msg_header_append_u32(msg, id) != 0) {
		// Arguably we could just discard and carry on.  But
		// dropping the connection is probably more helpful since
		// it lets the other side see that a problem occurred.
		// Plus it gives us a chance to reclaim some memory.
		goto malformed;
	}

	if (sock->raw) {
		nni_aio_set_msg(p->aio_putq, msg);
		nni_msgq_aio_put(sock->urq, p->aio_putq);
		return;
	}

	// Cooked mode.

	// Schedule another receive while we are processing this.
	nni_mtx_lock(&sock->mtx);
	nni_pipe_recv(p->pipe, p->aio_recv);

	// Look for a context to receive it.
	if ((nni_idhash_find(sock->reqids, id, (void **) &ctx) != 0) ||
	    (ctx->repmsg != NULL)) {
		nni_mtx_unlock(&sock->mtx);
		// No waiting context, or context already has a message.
		// Discard the message.
		nni_msg_free(msg);
		return;
	}

	// We have our match, so we can remove this.
	nni_list_node_remove(&ctx->sqnode);
	nni_idhash_remove(sock->reqids, id);
	ctx->reqid = 0;
	if (ctx->reqmsg != NULL) {
		nni_msg_free(ctx->reqmsg);
		ctx->reqmsg = NULL;
	}

	// Is there an aio waiting for us?
	if ((aio = ctx->aio) != NULL) {
		ctx->aio = NULL;
		nni_aio_set_msg(aio, msg);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
	} else {
		// No AIO, so stash msg.  Receive will pick it up later.
		ctx->repmsg = msg;
		nni_pollable_raise(ctx->recvable);
	}
	nni_mtx_unlock(&sock->mtx);
	return;

malformed:
	nni_msg_free(msg);
	nni_pipe_stop(p->pipe);
}

static void
req0_ctx_timeout(void *arg)
{
	req0_ctx * ctx  = arg;
	req0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	if ((ctx->reqmsg != NULL) && (!sock->closed)) {
		if (!nni_list_node_active(&ctx->sqnode)) {
			nni_list_append(&sock->sendq, ctx);
		}
		req0_run_sendq(sock);
	}
	nni_mtx_unlock(&sock->mtx);
}

static int
req0_ctx_init(void **cpp, void *sarg)
{
	req0_sock *sock = sarg;
	req0_ctx * ctx;
	int        rv;

	if ((ctx = NNI_ALLOC_STRUCT(ctx)) == NULL) {
		return (NNG_ENOMEM);
	}

	if (((rv = nni_pollable_alloc(&ctx->sendable)) != 0) ||
	    ((rv = nni_pollable_alloc(&ctx->recvable)) != 0)) {
		nni_pollable_free(ctx->sendable);
		nni_pollable_free(ctx->recvable);
		NNI_FREE_STRUCT(ctx);
		return (rv);
	}

	// We can *always* send.
	nni_pollable_raise(ctx->sendable);
	nni_timer_init(&ctx->timer, req0_ctx_timeout, ctx);

	nni_mtx_lock(&sock->mtx);
	ctx->sock  = sock;
	ctx->aio   = NULL;
	ctx->retry = sock->sctx.retry;
	nni_mtx_unlock(&sock->mtx);

	*cpp = ctx;
	return (0);
}

static void
req0_ctx_fini(void *arg)
{
	req0_ctx * ctx  = arg;
	req0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	req0_ctx_reset(ctx);
	nni_mtx_unlock(&sock->mtx);

	nni_timer_cancel(&ctx->timer);
	nni_timer_fini(&ctx->timer);

	nni_pollable_free(ctx->recvable);
	nni_pollable_free(ctx->sendable);

	NNI_FREE_STRUCT(ctx);
}

static int
req0_ctx_setopt_resendtime(void *arg, const void *buf, size_t sz, int typ)
{
	req0_ctx *ctx = arg;
	return (nni_copyin_ms(&ctx->retry, buf, sz, typ));
}

static int
req0_ctx_getopt_resendtime(void *arg, void *buf, size_t *szp, int typ)
{
	req0_ctx *ctx = arg;
	return (nni_copyout_ms(ctx->retry, buf, szp, typ));
}

static int
req0_ctx_getopt_sendfd(void *arg, void *buf, size_t *szp, int typ)
{
	req0_ctx *ctx = arg;
	int       rv;
	int       fd;

	if ((rv = nni_pollable_getfd(ctx->sendable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, typ));
}

static int
req0_ctx_getopt_recvfd(void *arg, void *buf, size_t *szp, int typ)
{
	req0_ctx *ctx = arg;
	int       rv;
	int       fd;

	if ((rv = nni_pollable_getfd(ctx->recvable, &fd)) != 0) {
		return (rv);
	}

	return (nni_copyout_int(fd, buf, szp, typ));
}

static void
req0_run_sendq(req0_sock *s)
{
	req0_ctx *ctx;

	// Note: This routine should be called with the socket lock held.
	// Also, this should only be called while handling cooked mode
	// requests.
	if (nni_list_empty(&s->sendq)) {
		return;
	}

	while ((ctx = nni_list_first(&s->sendq)) != NULL) {
		nni_msg *  msg;
		req0_pipe *p;

		if ((p = nni_list_first(&s->readypipes)) == NULL) {
			return;
		}

		// We have a place to send it, so go ahead do the send.
		// If a sending error occurs that causes the message to
		// be dropped, we rely on the resend timer to pick it up.
		nni_list_remove(&s->sendq, ctx);

		// Schedule a resubmit timer.  We only do this if we got
		// a pipe to send to.  Otherwise, we should get handled
		// the next time that the sendq is run.
		nni_timer_schedule(&ctx->timer, nni_clock() + ctx->retry);

		if (nni_msg_dup(&msg, ctx->reqmsg) != 0) {
			// Oops.  Well, keep trying each context; maybe
			// one of them will get lucky.
			continue;
		}

		// Put us on the pipe list of active contexts.
		// This gives the pipe a chance to kick a resubmit
		// if the pipe is removed.
		nni_list_node_remove(&ctx->pnode);
		nni_list_append(&p->ctxs, ctx);

		nni_list_remove(&s->readypipes, p);
		nni_list_append(&s->busypipes, p);
		nni_aio_set_msg(p->aio_sendcooked, msg);
		nni_pipe_send(p->pipe, p->aio_sendcooked);
	}
}

void
req0_ctx_reset(req0_ctx *ctx)
{
	req0_sock *sock = ctx->sock;
	// Call with sock lock held!

	// We cannot safely "wait" using nni_timer_cancel, but this removes
	// any scheduled timer activation.  If the timeout is already running
	// concurrently, it will still run.  It should do nothing, because
	// we toss the reqmsg.  There is still a very narrow race if the
	// timeout fires, but doesn't actually start running before we
	// both finish this function, *and* manage to reschedule another
	// request.  The consequence of that occurring is that the request
	// will be emitted on the wire twice.  This is not actually tragic.
	nni_timer_schedule(&ctx->timer, NNI_TIME_NEVER);

	nni_list_node_remove(&ctx->pnode);
	nni_list_node_remove(&ctx->sqnode);
	if (ctx->reqid != 0) {
		nni_idhash_remove(sock->reqids, ctx->reqid);
		ctx->reqid = 0;
	}
	if (ctx->reqmsg != NULL) {
		nni_msg_free(ctx->reqmsg);
		ctx->reqmsg = NULL;
	}
	if (ctx->repmsg != NULL) {
		nni_msg_free(ctx->repmsg);
		ctx->repmsg = NULL;
	}
}

static void
req0_ctx_cancel(nni_aio *aio, int rv)
{
	req0_ctx * ctx  = nni_aio_get_prov_data(aio);
	req0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	if (ctx->aio != aio) {
		// already completed, ignore this.
		nni_mtx_unlock(&sock->mtx);
		return;
	}
	ctx->aio = NULL;

	// Cancellation of a pending receive is treated as aborting the
	// entire state machine.  This allows us to preserve the semantic of
	// exactly one receive operation per send operation, and should
	// be the least surprising for users.  The main consequence is that
	// if a receive operation is completed (in error or otherwise), the
	// user must submit a new send operation to restart the state machine.
	req0_ctx_reset(ctx);

	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&sock->mtx);
}

static void
req0_ctx_recv_locked(req0_ctx *ctx, nni_aio *aio)
{
	nni_msg *msg;

	if (nni_aio_start(aio, req0_ctx_cancel, ctx) != 0) {
		return;
	}
	if ((ctx->aio != NULL) ||
	    ((ctx->reqmsg == NULL) && (ctx->repmsg == NULL))) {
		// We have already got a pending cooked receive, or
		// we have not tried to send a request yet.  Either of
		// these violate our basic state assumptions.
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}

	if ((msg = ctx->repmsg) != NULL) {
		ctx->repmsg = NULL;

		// We have got a message to pass up, yay!

		nni_aio_set_msg(aio, msg);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_pollable_clear(ctx->recvable);
	} else {
		// No message yet, so post the wait.
		ctx->aio = aio;
	}
}

static void
req0_ctx_recv(void *arg, nni_aio *aio)
{
	req0_ctx * ctx  = arg;
	req0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	req0_ctx_recv_locked(ctx, aio);
	nni_mtx_unlock(&sock->mtx);
}

static void
req0_ctx_send_locked(req0_ctx *ctx, nni_aio *aio)
{
	req0_sock *sock = ctx->sock;
	nng_msg *  msg  = nni_aio_get_msg(aio);
	uint64_t   id;
	size_t     len;
	int        rv;

	// Sending a new requst cancels the old one, including any
	// outstanding reply.
	if (ctx->aio != NULL) {
		nni_aio_finish_error(ctx->aio, NNG_ECANCELED);
		ctx->aio = NULL;
	}

	// This resets the entire state machine.
	req0_ctx_reset(ctx);

	// Insert us on the per ID hash list, so that receives can find us.
	if ((rv = nni_idhash_alloc(sock->reqids, &id, ctx)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	ctx->reqid  = (uint32_t) id;
	ctx->reqmsg = msg;
	len         = nni_msg_len(msg);
	if ((rv = nni_msg_header_append_u32(msg, ctx->reqid)) != 0) {
		nni_idhash_remove(sock->reqids, id);
		nni_aio_finish_error(aio, rv);
		return;
	}

	// Stick us on the sendq list.
	nni_list_append(&sock->sendq, ctx);

	// We are adding to the sendq, so run it.
	req0_run_sendq(sock);

	nni_aio_finish(aio, 0, len);
}

static void
req0_ctx_send(void *arg, nni_aio *aio)
{
	req0_ctx * ctx  = arg;
	req0_sock *sock = ctx->sock;

	nni_mtx_lock(&sock->mtx);
	req0_ctx_send_locked(ctx, aio);
	nni_mtx_unlock(&sock->mtx);
}

static void
req0_sock_send(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	req0_ctx_send_locked(&s->sctx, aio);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_sock_send_raw(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
req0_sock_recv(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	req0_ctx_recv_locked(&s->sctx, aio);
	nni_mtx_unlock(&s->mtx);
}

static void
req0_sock_recv_raw(void *arg, nni_aio *aio)
{
	req0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static int
req0_sock_setopt_maxttl(void *arg, const void *buf, size_t sz, int typ)
{
	req0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, typ));
}

static int
req0_sock_getopt_maxttl(void *arg, void *buf, size_t *szp, int typ)
{
	req0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, typ));
}

static int
req0_sock_setopt_resendtime(void *arg, const void *buf, size_t sz, int typ)
{
	req0_sock *s = arg;
	return (req0_ctx_setopt_resendtime(&s->sctx, buf, sz, typ));
}

static int
req0_sock_getopt_resendtime(void *arg, void *buf, size_t *szp, int typ)
{
	req0_sock *s = arg;
	return (req0_ctx_getopt_resendtime(&s->sctx, buf, szp, typ));
}

static int
req0_sock_getopt_recvfd(void *arg, void *buf, size_t *szp, int typ)
{
	req0_sock *s = arg;
	return (req0_ctx_getopt_recvfd(&s->sctx, buf, szp, typ));
}

static int
req0_sock_getopt_sendfd(void *arg, void *buf, size_t *szp, int typ)
{
	req0_sock *s = arg;
	return (req0_ctx_getopt_sendfd(&s->sctx, buf, szp, typ));
}

static nni_proto_pipe_ops req0_pipe_ops = {
	.pipe_init  = req0_pipe_init,
	.pipe_fini  = req0_pipe_fini,
	.pipe_start = req0_pipe_start,
	.pipe_stop  = req0_pipe_stop,
};

static nni_proto_ctx_option req0_ctx_options[] = {
	{
	    .co_name   = NNG_OPT_REQ_RESENDTIME,
	    .co_type   = NNI_TYPE_DURATION,
	    .co_getopt = req0_ctx_getopt_resendtime,
	    .co_setopt = req0_ctx_setopt_resendtime,
	},
	{
	    .co_name   = NNG_OPT_RECVFD,
	    .co_type   = NNI_TYPE_INT32,
	    .co_setopt = NULL,
	    .co_getopt = req0_ctx_getopt_recvfd,
	},
	{
	    .co_name   = NNG_OPT_SENDFD,
	    .co_type   = NNI_TYPE_INT32,
	    .co_setopt = NULL,
	    .co_getopt = req0_ctx_getopt_sendfd,
	},
	{
	    .co_name = NULL,
	},
};

static nni_proto_ctx_ops req0_ctx_ops = {
	.ctx_init    = req0_ctx_init,
	.ctx_fini    = req0_ctx_fini,
	.ctx_recv    = req0_ctx_recv,
	.ctx_send    = req0_ctx_send,
	.ctx_options = req0_ctx_options,
};

static nni_proto_sock_option req0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = req0_sock_getopt_maxttl,
	    .pso_setopt = req0_sock_setopt_maxttl,
	},
	{
	    .pso_name   = NNG_OPT_REQ_RESENDTIME,
	    .pso_type   = NNI_TYPE_DURATION,
	    .pso_getopt = req0_sock_getopt_resendtime,
	    .pso_setopt = req0_sock_setopt_resendtime,
	},
	{
	    .pso_name   = NNG_OPT_RECVFD,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = req0_sock_getopt_recvfd,
	    .pso_setopt = NULL,
	},
	{
	    .pso_name   = NNG_OPT_SENDFD,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = req0_sock_getopt_sendfd,
	    .pso_setopt = NULL,
	},
	// terminate list
	{
	    .pso_name = NULL,
	},
};

static nni_proto_sock_option req0_sock_options_raw[] = {
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = req0_sock_getopt_maxttl,
	    .pso_setopt = req0_sock_setopt_maxttl,
	},
	// terminate list
	{
	    .pso_name = NULL,
	},
};

static nni_proto_sock_ops req0_sock_ops = {
	.sock_init    = req0_sock_init,
	.sock_fini    = req0_sock_fini,
	.sock_open    = req0_sock_open,
	.sock_close   = req0_sock_close,
	.sock_options = req0_sock_options,
	.sock_send    = req0_sock_send,
	.sock_recv    = req0_sock_recv,
};

static nni_proto req0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REQ_V0, "req" },
	.proto_peer     = { NNI_PROTO_REP_V0, "rep" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &req0_sock_ops,
	.proto_pipe_ops = &req0_pipe_ops,
	.proto_ctx_ops  = &req0_ctx_ops,
};

int
nng_req0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &req0_proto));
}

static nni_proto_sock_ops req0_sock_ops_raw = {
	.sock_init    = req0_sock_init_raw,
	.sock_fini    = req0_sock_fini,
	.sock_open    = req0_sock_open,
	.sock_close   = req0_sock_close,
	.sock_options = req0_sock_options_raw,
	.sock_send    = req0_sock_send_raw,
	.sock_recv    = req0_sock_recv_raw,
};

static nni_proto req0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REQ_V0, "req" },
	.proto_peer     = { NNI_PROTO_REP_V0, "rep" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &req0_sock_ops_raw,
	.proto_pipe_ops = &req0_pipe_ops,
	.proto_ctx_ops  = NULL, // raw mode does not support contexts
};

int
nng_req0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &req0_proto_raw));
}
