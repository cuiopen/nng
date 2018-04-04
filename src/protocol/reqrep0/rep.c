//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "protocol/reqrep0/rep.h"

// Response protocol.  The REP protocol is the "reply" side of a
// request-reply pair.  This is useful for building RPC servers, for
// example.

#ifndef NNI_PROTO_REQ_V0
#define NNI_PROTO_REQ_V0 NNI_PROTO(3, 0)
#endif

#ifndef NNI_PROTO_REP_V0
#define NNI_PROTO_REP_V0 NNI_PROTO(3, 1)
#endif

typedef struct rep0_pipe rep0_pipe;
typedef struct rep0_sock rep0_sock;
typedef struct rep0_ctx  rep0_ctx;

static void rep0_pipe_send_cb(void *);
static void rep0_pipe_recv_cb(void *);
static void rep0_pipe_fini(void *);

struct rep0_ctx {
	rep0_sock *sock;
	char *     btrace;
	size_t     btrace_len;
	size_t     btrace_size;
	int        ttl;
	uint32_t   pipe_id;
};

// rep0_sock is our per-socket protocol private structure.
struct rep0_sock {
	nni_mtx     lk;
	int         ttl;
	nni_idhash *pipes;
	nni_list    recvable; // list of pipes with data to receive
	nni_list    recvq;
	bool        closed;
	rep0_ctx *  ctx;
};

// rep0_pipe is our per-pipe protocol private structure.
struct rep0_pipe {
	nni_pipe *    pipe;
	rep0_sock *   rep;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	nni_list_node recvable;  // receivable list linkage
	nni_list      aio_sendq; // pending aios from contexts.
};

static void
rep0_ctx_fini(void *arg)
{
	rep0_ctx *ctx = arg;
	nni_free(ctx->btrace, ctx->btrace_size);
	NNI_FREE_STRUCT(ctx);
}

static int
rep0_ctx_init(void **ctxp, void *sarg)
{
	rep0_sock *s = sarg;
	rep0_ctx * ctx;

	if ((ctx = NNI_ALLOC_STRUCT(ctx)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_lock(&s->lk);
	ctx->ttl = s->ttl;
	nni_mtx_unlock(&s->lk);

	ctx->btrace_size = ctx->ttl * sizeof(uint32_t);
	if ((ctx->btrace = nni_alloc(ctx->btrace_size)) == NULL) {
		NNI_FREE_STRUCT(ctx);
		return (NNG_ENOMEM);
	}
	ctx->btrace_len = 0;
	ctx->sock       = s;
	*ctxp           = ctx;
	return (0);
}

static void
rep0_ctx_cancel_send(nni_aio *aio, int rv)
{
	rep0_sock *s = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&s->lk);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&s->lk);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&s->lk);

	nni_msg_header_clear(nni_aio_get_msg(aio)); // reset the headers
	nni_aio_finish_error(aio, rv);
}

static void
rep0_ctx_send_locked(rep0_ctx *ctx, nni_aio *aio)
{
	rep0_sock *s = ctx->sock;
	rep0_pipe *p;
	nni_msg *  msg;
	int        rv;
	size_t     btlen;
	uint32_t   p_id; // pipe id

	msg = nni_aio_get_msg(aio);
	nni_msg_header_clear(msg);

	btlen = ctx->btrace_len;
	p_id  = ctx->pipe_id;

	// Assert "completion" of the previous req request.  This ensures
	// exactly one send for one receive ordering.
	ctx->btrace_len = 0;
	ctx->pipe_id    = 0;

	if (nni_aio_start(aio, rep0_ctx_cancel_send, s) != 0) {
		return;
	}
	if (s->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (btlen == 0) {
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if ((rv = nni_msg_header_append(msg, ctx->btrace, btlen)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	if ((rv = nni_idhash_find(s->pipes, p_id, (void **) &p)) != 0) {
		// Pipe is gone.  Make this look like a good send to avoid
		// disrupting the state machine.  We don't care if the peer
		// lost interest in our reply.
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
		return;
	}
	nni_list_append(&p->aio_sendq, aio);
	if (nni_list_first(&p->aio_sendq) == aio) {
		nni_aio_set_msg(aio, NULL);
		nni_aio_set_msg(p->aio_send, msg);
		nni_pipe_send(p->pipe, p->aio_send);
	}
}

static void
rep0_ctx_send(void *arg, nni_aio *aio)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;

	nni_mtx_lock(&s->lk);
	rep0_ctx_send_locked(ctx, aio);
	nni_mtx_unlock(&s->lk);
}

static void
rep0_sock_fini(void *arg)
{
	rep0_sock *s = arg;

	nni_idhash_fini(s->pipes);
	if (s->ctx != NULL) {
		rep0_ctx_fini(s->ctx);
	}
	nni_mtx_fini(&s->lk);
	NNI_FREE_STRUCT(s);
}

static int
rep0_sock_init(void **sp, nni_sock *sock)
{
	rep0_sock *s;
	int        rv;

	NNI_ARG_UNUSED(sock);

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->lk);
	if ((rv = nni_idhash_init(&s->pipes)) != 0) {
		rep0_sock_fini(s);
		return (rv);
	}

	nni_aio_list_init(&s->recvq);
	NNI_LIST_INIT(&s->recvable, rep0_pipe, recvable);

	s->ttl = 8;

	if ((rv = rep0_ctx_init((void **) &s->ctx, s)) != 0) {
		rep0_sock_fini(s);
		return (rv);
	}

	*sp = s;

	return (0);
}

static void
rep0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
rep0_sock_close(void *arg)
{
	rep0_sock *s = arg;
	nni_aio *  aio;

	nni_mtx_lock(&s->lk);
	s->closed = true;
	while ((aio = nni_list_first(&s->recvq)) != NULL) {
		nni_list_remove(&s->recvq, aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->lk);
}

static void
rep0_pipe_fini(void *arg)
{
	rep0_pipe *p = arg;

	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	NNI_FREE_STRUCT(p);
}

static int
rep0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	rep0_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_send, rep0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, rep0_pipe_recv_cb, p)) != 0)) {
		rep0_pipe_fini(p);
		return (rv);
	}

	nni_aio_list_init(&p->aio_sendq);

	p->pipe = pipe;
	p->rep  = s;
	*pp     = p;
	return (0);
}

static int
rep0_pipe_start(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	int        rv;

	if ((rv = nni_idhash_insert(s->pipes, nni_pipe_id(p->pipe), p)) != 0) {
		return (rv);
	}

	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
rep0_pipe_stop(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	nni_aio *  aio;

	nni_mtx_lock(&s->lk);
	while ((aio = nni_list_first(&p->aio_sendq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->lk);

	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);

	nni_idhash_remove(s->pipes, nni_pipe_id(p->pipe));
}

static void
rep0_pipe_send_cb(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	nni_aio *  done;
	nni_aio *  aio;
	size_t     len;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}
	len = nni_aio_count(p->aio_send);

	nni_mtx_lock(&s->lk);
	done = nni_list_first(&p->aio_sendq);
	nni_list_remove(&p->aio_sendq, done);

	if ((aio = nni_list_first(&p->aio_sendq)) != NULL) {
		nni_msg *msg = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_set_msg(p->aio_send, msg);
		nni_pipe_send(p->pipe, p->aio_send);
	}

	nni_aio_finish(done, 0, len);
	nni_mtx_unlock(&s->lk);
#if 0
	nni_aio_set_synch(done);
#endif
}

static void
rep0_cancel_recv(nni_aio *aio, int rv)
{
	rep0_sock *s = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&s->lk);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->lk);
}

static void
rep0_ctx_recv(void *arg, nni_aio *aio)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;
	rep0_pipe *p;
	size_t     len;
	nni_msg *  msg;

	nni_mtx_lock(&s->lk);
	if (nni_aio_start(aio, rep0_cancel_recv, s) != 0) {
		nni_mtx_unlock(&s->lk);
		return;
	}
	if (s->closed) {
		nni_mtx_unlock(&s->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((p = nni_list_first(&s->recvable)) == NULL) {
		nni_aio_set_prov_extra(aio, 0, ctx);
		nni_list_append(&s->recvq, aio);
		nni_mtx_unlock(&s->lk);
		return;
	}
	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_list_remove(&s->recvable, p);
	nni_pipe_recv(p->pipe, p->aio_recv);

	len = nni_msg_header_len(msg);
	if ((len == 0) || (len > ctx->btrace_size)) {
		// We cannot accept it, bad header.  Discard.
		nni_msg_free(msg);
		nni_mtx_unlock(&s->lk);
		return;
	}
	memcpy(ctx->btrace, nni_msg_header(msg), len);
	ctx->btrace_len = len;
	ctx->pipe_id    = nni_pipe_id(p->pipe);
	nni_mtx_unlock(&s->lk);

	nni_msg_header_clear(msg);
	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static int
rep0_ctx_setopt_maxttl(void *arg, const void *buf, size_t sz, int typ)
{
	rep0_ctx * ctx = arg;
	rep0_sock *s   = ctx->sock;
	int        rv;
	int        ttl;

	nni_mtx_lock(&s->lk);
	rv = nni_copyin_int(&ttl, buf, sz, 1, 255, typ);
	if (rv != 0) {
		nni_mtx_unlock(&s->lk);
		return (rv);
	}
	if ((ttl * sizeof(uint32_t)) > ctx->btrace_size) {
		void *btbuf;
		if ((btbuf = nni_alloc(ttl * sizeof(uint32_t))) == NULL) {
			nni_mtx_unlock(&s->lk);
			return (NNG_ENOMEM);
		}
		memcpy(btbuf, ctx->btrace, ctx->btrace_len);
		nni_free(ctx->btrace, ctx->btrace_size);
		ctx->btrace_size = ttl * sizeof(uint32_t);
		ctx->btrace      = btbuf;
	}
	nni_mtx_unlock(&s->lk);
	ctx->ttl = ttl;
	return (0);
}

static int
rep0_ctx_getopt_maxttl(void *arg, void *buf, size_t *szp, int typ)
{
	rep0_ctx *ctx = arg;
	return (nni_copyout_int(ctx->ttl, buf, szp, typ));
}

static void
rep0_pipe_recv_cb(void *arg)
{
	rep0_pipe *p = arg;
	rep0_sock *s = p->rep;
	rep0_ctx * ctx;
	nni_msg *  msg;
	int        rv;
	uint8_t *  body;
	nni_aio *  aio;
	size_t     len;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);

	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// Move backtrace from body to header
	for (;;) {
		int end = 0;

		if (nni_msg_len(msg) < 4) {
			// Peer is speaking garbage. Kick it.
			nni_msg_free(msg);
			nni_pipe_stop(p->pipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = (body[0] & 0x80) ? 1 : 0;
		rv   = nni_msg_header_append(msg, body, 4);
		if (rv != 0) {
			// Out of memory, so drop it.
			goto drop;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	len = nni_msg_header_len(msg);

	nni_mtx_lock(&s->lk);

	if ((aio = nni_list_first(&s->recvq)) == NULL) {
		// No one waiting to receive yet, holding pattern.
		nni_list_append(&s->recvable, p);
		nni_mtx_unlock(&s->lk);
		return;
	}
	ctx = nni_aio_get_prov_extra(aio, 0);
	if ((len == 0) || (len > (ctx->ttl * sizeof(uint32_t)))) {
		nni_mtx_unlock(&s->lk);
		goto drop;
	}

	nni_aio_set_msg(aio, msg);
	nni_aio_list_remove(aio);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, p->aio_recv);

	ctx->btrace_len = len;
	memcpy(ctx->btrace, nni_msg_header(msg), len);
	nni_msg_header_clear(msg);
	ctx->pipe_id = nni_pipe_id(p->pipe);

	nni_mtx_unlock(&s->lk);

	nni_aio_set_synch(aio);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
	return;

drop:
	nni_msg_free(msg);
	nni_pipe_recv(p->pipe, p->aio_recv);
}

static int
rep0_sock_setopt_maxttl(void *arg, const void *buf, size_t sz, int typ)
{
	rep0_sock *s = arg;
	return (rep0_ctx_setopt_maxttl(s->ctx, buf, sz, typ));
}

static int
rep0_sock_getopt_maxttl(void *arg, void *buf, size_t *szp, int typ)
{
	rep0_sock *s = arg;
	return (rep0_ctx_getopt_maxttl(s->ctx, buf, szp, typ));
}

static void
rep0_sock_send(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;

	rep0_ctx_send(s->ctx, aio);
}

static void
rep0_sock_recv(void *arg, nni_aio *aio)
{
	rep0_sock *s = arg;

	rep0_ctx_recv(s->ctx, aio);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops rep0_pipe_ops = {
	.pipe_init  = rep0_pipe_init,
	.pipe_fini  = rep0_pipe_fini,
	.pipe_start = rep0_pipe_start,
	.pipe_stop  = rep0_pipe_stop,
};

static nni_proto_ctx_option rep0_ctx_options[] = {
	{
	    .co_name   = NNG_OPT_MAXTTL,
	    .co_type   = NNI_TYPE_INT32,
	    .co_getopt = rep0_ctx_getopt_maxttl,
	    .co_setopt = rep0_ctx_setopt_maxttl,

	},
	// terminate list
	{
	    .co_name = NULL,
	},
};

static nni_proto_ctx_ops rep0_ctx_ops = {
	.ctx_init    = rep0_ctx_init,
	.ctx_fini    = rep0_ctx_fini,
	.ctx_send    = rep0_ctx_send,
	.ctx_recv    = rep0_ctx_recv,
	.ctx_options = rep0_ctx_options,
};

static nni_proto_sock_option rep0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = rep0_sock_getopt_maxttl,
	    .pso_setopt = rep0_sock_setopt_maxttl,
	},
	// terminate list
	{
	    .pso_name = NULL,
	},
};

static nni_proto_sock_ops rep0_sock_ops = {
	.sock_init    = rep0_sock_init,
	.sock_fini    = rep0_sock_fini,
	.sock_open    = rep0_sock_open,
	.sock_close   = rep0_sock_close,
	.sock_options = rep0_sock_options,
	.sock_send    = rep0_sock_send,
	.sock_recv    = rep0_sock_recv,
};

static nni_proto rep0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_REP_V0, "rep" },
	.proto_peer     = { NNI_PROTO_REQ_V0, "req" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_NOMSGQ,
	.proto_sock_ops = &rep0_sock_ops,
	.proto_pipe_ops = &rep0_pipe_ops,
	.proto_ctx_ops  = &rep0_ctx_ops,
};

int
nng_rep0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &rep0_proto));
}
