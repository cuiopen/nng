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

#include "core/nng_impl.h"

// Handshakes are HTTP headers.  They consist of either
// a request or response line, followed by key-value pairs (one per line),
// followed by an empty line.  Each line is terminated with a CRLF.
// Note that a given 'name' may be repeated, in which case its value can
// simply be appeneded to the prior value, seperated by a colon.
//
// GET <path> HTTP/1.1
// Host: <host>
// Upgrade: websocket
// Connection: Upgrade
// Origin: <somewhere> (not actually used?)
// Sec-WebSocket-Key: <xxxxx>
// Sec-WebSocket-Protocol: <x>
// Sec-WebSocket-Version: 13
// <empty>
//
// From server:
//
// HTTP/1.1 101 Switching Protocols
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Accept: <xxxx>
// Sec-WebSocket-Protocol: <x>
// <empty>
//
// Reasonable limits on header size: 8K for everything.
// Even the most borked implementation should not send more than that.
// Our maximum address length is 128 bytes.  So frankly even if we max that
// out we should be under 512 bytes (well); extra fields sent by clients,
// like client identifiers, should be *small*.  Certainly under 7.5KB.
//

struct ws_ep {
	int              mode; // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
	char             addr[NNG_MAXADDRLEN + 1];
	uint16_t         lproto; // local protocol
	uint16_t         rproto; // remote protocol
	size_t           rcvmax;
	char *           host;
	char *           path;
	nni_http_client *client; // only one of client or server is valid
	nni_http_server *server;
	nni_http_handler handler; // server only
};

// The most we will send in a single fragment.  We leave this pretty large,
// because if it is small the receiver will wind up having to reallocate
// messages a lot, and that is expensive.  If the value is *too* large,
// then the latency on handling control frames may become rather large.
// (Browsers and servers that send PING requests may become unhappy if it
// takes too long for them to get a PONG reply.)
#define WS_FRAGMENT_SIZE (1U << 20)

// WS_FRAGMENT_PREALLOC is used to indicate that we should preallocate
// data in this chunk size, when receiving a fragmented frame.  (Meaning,
// we will allocate this much extra at a time).  Large values can impact
// memory consumption negatively.  Small values will cause extra data copying
// and reallocations.  We only do this large preallocation once.  (So
// sending very large fragmented frames with websocket is going to have
// pretty poor performance.  This is a deficiency in the SP over websocket
// protocol -- we really would like to have the actual message size supplied.)
#define WS_FRAGMENT_PREALLOC (1U << 20)

// A substantial drawback is that we never know the actual overall message
// size.  We should fix this in a follow up to the RFC.

// Websocket binary message header structure:
//
// {
//      int fin:1;
//      int rsv:3;  -- must be zero
//      int opcode:4;
//      int mask:1;
//      int payload_len:7;
//      int extended_payload_len:16...64;
//        ... extended is 16bits if payload_len == 126
//        ... extended is 64bits if payload_len == 127
//        ... extended is absent otherwise (len <= 125)
//      int masking_key:32; (if mask == 1)
// }
//
// If the variable length of that header makes you want to vomit,
// rest assured that you are not alone.  So we will read the 16
// bits of the mandatory header parts, then use that to decide
// how many more bits to read -- between 0 and 96.
//
// client sends data with mask, server sends without
//
// opcodes:
// 0x0: continuation
// 0x1: text frame
// 0x2: binary frame
// 0x8: close
// 0x9: ping
// 0xa: pong

typedef enum ws_opcode {
	WS_CONT   = 0x00,
	WS_TEXT   = 0x01,
	WS_BINARY = 0x02,
	WS_CLOSE  = 0x08,
	WS_PING   = 0x09,
	WS_PONG   = 0x0A,
	WS_FINAL  = 0x80,
} ws_opcode;

typedef enum ws_rxstate {
	WS_RX_HEADER,
	WS_RX_CONTROL,
	WS_RX_PAYLOAD,
	WS_RX_CLOSE,
} ws_rxstate;

typedef enum ws_txstate {
	WS_TX_IDLE,
	WS_TX_DATA,
	WS_TX_CONTROL,
	WS_TX_CLOSE,
} ws_txstate;

// These are close reasons -- only the ones that can be sent over the
// wire are listed here.  RFC6455 reserves 1004, 1005, 1006, and 1015.
typedef enum ws_reason {
	WS_CLOSE_NORMAL_CLOSE  = 1000,
	WS_CLOSE_GOING_AWAY    = 1001,
	WS_CLOSE_PROTOCOL_ERR  = 1002,
	WS_CLOSE_UNSUPP_FORMAT = 1003,
	WS_CLOSE_INVALID_DATA  = 1007,
	WS_CLOSE_POLICY        = 1008,
	WS_CLOSE_TOO_BIG       = 1009,
	WS_CLOSE_NO_EXTENSION  = 1010,
	WS_CLOSE_INTERNAL      = 1011,
} ws_reason;

struct ws_pipe {
	int       mode;        // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
	nni_http *http;        // http transport
	uint8_t   mask[4];     // masking key
	uint8_t   rxhead[14];  // header buf (rx)
	uint8_t   rxctrl[125]; // control frame payload

	size_t     rxheadlen;
	size_t     rxctrllen;
	size_t     rxpaylen;
	size_t     rxresid; // remaining rx payload (frame)
	bool       rxtext;  // frame is TEXT type (must check UTF-8)
	size_t     rcvmax;  // inherited from EP
	ws_rxstate rxstate;

	uint16_t   txclose; // if set, then we should send this close code
	uint8_t    txhead[14];
	uint8_t    txctrl[125]; // only for ping/pong really
	size_t     txheadlen;
	size_t     txctrllen;
	size_t     txresid;
	size_t     txpaylen;
	ws_txstate txstate;

	size_t rxbuflen;
	size_t txbuflen;
	size_t txresid;
	size_t maxfrag; // maximum frame size

	nni_aio *user_txaio;
	nni_aio *user_rxaio;

	nni_aio *txaio;
	nni_aio *rxaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;

	uint8_t ws_key[16]; // Raw key value
};

static void
ws_pipe_recv_cb_payload(ws_pipe *p, size_t n)
{
	uint8_t *body = nni_msg_body(p->rxmsg);
	uint8_t *end;
	nni_aio *aio = p->rxaio;

	NNI_ASSSERT(n <= p->rxresid);
	p->rxresid -= n;

	end = body + nni_msg_len(p->rxmsg);

	if (p->rxresid != 0) {
		// Still need more data for this frame, continue.
		aio->a_niov           = 1;
		aio->a_iov[0].iov_buf = end - p->rxresid;
		aio->a_iov[0].iov_len = p->rxresid;
		nni_http_read_full(aio);
		return;
	}

	if (p->rxhead[1] & 0x80) {
		uint8_t *beg = end - p->rxpaylen;
		// Unmask the data.  This is done at the frame level.
		for (int i = 0; i < p->rxlen; i++) {
			beg[i] = beg[i] ^ p->mask[i % 4];
		}
	}

	if (p->rxbuf[0] & 0x80) {
		// This was final frame.
		// XXX: check for UTF-8 validity if p->rxtext is true.
		aio           = p->user_rxaio;
		p->user_rxaio = NULL;
		nni_aio_finish_msg(aio, p->rxmsg);
		p->rxmsg     = NULL;
		p->rxpaylen  = 0;
		p->rxheadlen = 0;
		p->rxctrllen = 0;
		p->rxresid   = 0;
		p->rxstate   = WS_RX_HEADER;
		p->rxtext    = false;
		return;
	}

	// We need more data -- (more frames).
	p->rxstate            = WS_RX_HEADER;
	p->rxheadlen          = 0;
	p->rxctrllen          = 0;
	p->rxresid            = 0;
	p->rxpaylen           = 0;
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = sizeof(uint16_t);
	aio->a_iov[0].iov_buf = p->rxhead;
	nni_http_read_full(p->http, aio);
}

static void
ws_apply_mask(nni_aio *aio, uint32_t maskval)
{
	uint8_t  mask[sizeof(uint32_t)];
	int      i, j, k;
	uint8_t *data;

	NNI_PUT32(mask, maskval);
	i = 0; // count of bytes masked thus far
	j = 1; // index to the iov (iov[0] is always head not payload)
	k = 0; // index within the iov entry
	for (;;) {
		if (j == aio->a_niov) {
			break;
		}
		if (k >= aio->a_iov[j].iov_len) {
			j++;
			k = 0;
			continue;
		}
		data = aio->a_iov[j].iov_buf;
		data[k] ^= mask[i % 4];
		k++;
		i++;
	}
}

static void
ws_pipe_send_cancel(nni_aio *aio, int rv)
{
	nni_mtx_lock(&p->mtx);
	if (p->user_txaio == aio) {
		if (p->txstate == WS_TX_DATA) {
			// Only abort the bottom if its actually in flight.
			nni_aio_cancel(p->txaio, NNG_ECANCELED);
		}
		if (p->txmsg != NULL) {
			nni_msg_free(p->txmsg);
			p->txmsg = NULL;
		}
		p->user_txaio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send_cb(void *arg)
{
	ws_pipe *p   = arg;
	nni_aio *aio = p->txaio;
	int      rv;

	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		if ((aio = p->user_txaio) != NULL) {
			p->user_txaio = NULL;
			nni_aio_finish_error(aio, rv);
		}
		nni_http_close(p->http);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->txstate == WS_TX_CLOSE) {
		// If we sent the close frame, then shut things down.
		nni_http_close(h->http);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if ((p->txstate == WS_TX_DATA) && (nni_msg_len(p->txmsg) == NULL)) {
		nni_msg_free(p->txmsg);
		p->txmsg   = NULL;
		p->txstate = WS_TX_IDLE;
	}
	ws_pipe_send_start(p);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send_start(ws_pipe *p)
{
	// After sending a close frame, we do nothing else.
	if (p->txstate == WS_TX_CLOSE) {
		return;
	}

	if (p->txclose) {
		// We need to send a close frame - this overrides any
		// other control frame.
		NNI_PUT16(p->txctrl, p->txclose);
		p->txctrllen = sizeof(uint16_t);
	}

	if (p->txctrllen) {
		// It turns out that we only send PONGs and CLOSE.
		// PONG data will already have been loaded in txctrl.
		p->txhead[0] = p->txclose ? WS_CLOSE : WS_PONG;
		p->txhead[1] = p->txctrllen;

		p->txstate       = p->txclose ? WS_TX_CLOSE : WS_TX_CONTROL;
		p->txaio->a_niov = 2;
		p->txaio->a_iov[1].iov_buf = p->txctrl;
		p->txaio->a_iov[1].iov_len = p->txctrllen;
		if (p->mode == NNI_EP_MODE_DIAL) {
			uint32_t r = nni_random();
			p->txhead[1] |= 0x80;
			NNI_PUT32(p->txhead + 2, r);
			p->txheadlen += sizeof(uint32_t);
			ws_apply_mask(p->txaio, r);
		}

		p->txaio->a_iov[0].iov_buf = p->txhead;
		p->txaio->a_iov[0].iov_len = p->txheadlen;

		// Reset this to zero, so we don't keep doing it.
		p->txctrllen = 0;

		nni_http_write_full(p->http, p->txaio);
		return;
	}

	if (p->txmsg != NULL) {
		int      niov = 1;
		uint8_t *data;
		size_t   size;
		size_t   n;

		// We send the complete header, always, if present.
		if (((data = nni_msg_header(p->txmsg)) != NULL) &&
		    ((size = nni_msg_header_len(p->txmsg)) != 0)) {
			p->txaio->a_iov[niov].iov_len = size;
			p->txaio->a_iov[niov].iov_buf = data;
			niov++;
			nni_msg_header_clear(p->txmsg);
		}

		if (size < WS_FRAGMENT_SIZE) {
			data = nni_msg_body(p->txmsg);
			n    = nni_msg_len(p->txmsg);
			if (n > (WS_FRAGMENT_SIZE - size)) {
				n = WS_FRAGMENT_SIZE - size;
			}

			p->txaio->a_iov[niov].iov_len = n;
			p->txaio->a_iov[niov].iov_buf = data;
			niov++;
			size += n;
			nni_msg_trim(p->txmsg, n);
		}

		op           = p->textmode ? WS_TEXT : WS_BINARY;
		p->txhead[0] = p->txstate == WS_TX_IDLE ? op : WS_CONT;
		if (nni_msg_len(p->txmsg) == 0) {
			p->txhead[0] |= WS_FINAL;
		}
		p->txheadlen = sizeof(uint16_t);

		if (size <= 125) {
			p->txhead[1] = (uint8_t) size;
		} else if (size < 65536) {
			p->txhead[1] = 126;
			NNI_PUT16(p->txhead + 2, (uint16_t) size);
			p->txheadlen += sizeof(uint16_t);
		} else {
			p->txhead[1] = 127;
			NNI_PUT64(p->txhead + 2, size);
			p->txheadlen += sizeof(uint64_t);
		}

		if (p->mode == NNI_EP_MODE_DIAL) {
			uint32_t r = nni_random();
			NNI_PUT32(p->txhead + p->txheadlen, r);
			p->txheadlen += sizeof(uint32_t);
			p->txhead[1] |= 0x80; // note masking
			ws_apply_mask(p->txaio, r);
		}

		p->txaio->a_iov[0].iov_buf = p->txhead;
		p->txaio->a_iov[0].iov_len = p->txheadlen;
		p->txaio->a_niov           = niov;
		p->txstate                 = WS_TX_DATA;
		nni_http_write_full(p->http, p->txaio);
		return;
	}
}

static void
ws_pipe_send_close(ws_pipe *p, int rv)
{
	nni_aio *aio;
	uint16_t code;

	switch (rv) {
	case NNG_EPROTO:
		code = WS_CLOSE_PROTOCOL_ERR;
		break;
	case NNG_EMSGSIZE:
		code = WS_CLOSE_TOO_BIG;
		break;
	case NNG_ECLOSED:
		code = WS_CLOSE_NORMAL_CLOSE;
		break;
	case NNG_ECANCELED:
		code = WS_CLOSE_GOING_AWAY;
		break;
	case NNG_ENOMEM:
	default:
		code = WS_CLOSE_INTERNAL;
		break;
	}

	// XXX: REVIEW ME!
	if ((aio = p->user_rxaio) != NULL) {
		p->user_rxaio = NULL;
		nni_aio_finish_error(aio, rv);
	}

	p->rxstate = WS_RX_CLOSE;
	p->txclose = code;

	if (p->txstate == WS_TX_IDLE) {
		ws_pipe_send_start(p);
	}
}

static void
ws_pipe_send_pong(ws_pipe *p, uint8_t *payload, size_t paylen)
{
#if 0
	p->txhead[0] = 0x80 | WS_PONG;
	memcpy(p->txctrl, payload, paylen);
	p->txctrllen = paylen;
#endif
}

static void
ws_pipe_recv_cb_control(ws_pipe *p, size_t n)
{
	nni_aio *aio = p->rxaio;
	nni_msg *msg;
	uint8_t  hdr[2];

	// Read the control data.
	p->rxresid -= n;
	if (p->rxresid != 0) {
		// Still need more data for this frame, continue.
		aio->a_niov           = 1;
		aio->a_iov[0].iov_buf = p->rxctrl + p->rxctrllen - p->rxresid;
		aio->a_iov[0].iov_len = p->rxresid;
		nni_http_read_full(aio);
		return;
	}

	if (p->rxhead[1] & 0x80) {
		// unmask it.
		for (int i = 0; i < p->rxctrllen; i++) {
			p->rxctrl[i] ^= p->mask[i % 4];
		}
	}

	switch (p->rxhead[0] & 0xf) {
	case WS_PONG:
		// Discard pong responses, we never send ping.
		return;
	case WS_PING:
		ws_pipe_send_pong(p, p->rxctrl, p->rxctrllen);
		return;
	case WS_CLOSE:
		ws_pipe_send_close(p, NNG_ECLOSED);
		return;
	default:
		ws_pipe_send_close(p, NNG_EPROTO);
		return;
	}
}

static void
ws_pipe_recv_cb_header(ws_pipe *p, size_t n)
{
	nni_aio *aio = p->rxaio;
	size_t   allocsz;

	// we are reading header data.
	p->rxheadlen += n;
	need = sizeof(uint16_t);

	if (p->rxheadlen >= sizeof(uint16_t)) {
		switch (p->rxhead[1] & 0x7f) {
		case 127:
			need += 8;
			break;
		case 126:
			need += 2;
			break;
		}
		if (p->rxhead[1] & 0x80) {
			// mask needed
			need += 4;
		}
	}
	if (p->rxheadlen < need) {
		aio->a_niov           = 1;
		aio->a_iov[0].iov_buf = p->rxhead + p->rxheadlen;
		aio->a_iov[0].iov_len = need - p->rxheadlen;
		nni_http_read_full(p->http, aio);
		return;
	}

	switch (p->rxhead[1] & 0x7f) {
	case 127:
		p->rxpaylen = NNI_GET64(p->rxhead + 2, paylen);
		break;
	case 126:
		p->rxpaylen = NNI_GET16(p->rxhead + 2, paylen);
		break;
	default:
		p->rxpaylen = p->rxhead[1] & 0x7f;
		break;
	}

	if (p->rxhead[1] & 0x80) {
		// Save the masking key.
		memcpy(p->mask, p->rxhead - p->rxheadlen, sizeof(uint32_t));
		// Server MUST NOT send masked frames.
		if (p->mode == NNI_EP_MODE_DIAL) {
			ws_pipe_send_close(p, NNG_EPROTO);
			return;
		}
	} else if ((p->mode == NNI_EP_MODE_LISTEN) && (p->rxpaylen > 0)) {
		// Client MUST send masked frames.  We generously allow
		// for them to skip sending a mask if there is no data.
		ws_pipe_send_close(p, NNG_EPROTO);
		return;
	}

	if (p->rxhead[0] & 0x70) {
		// Reserved bits must be zero.
		ws_pipe_send_close(p, NNG_EPROTO);
		return;
	}

	// opcode
	switch (p->rxhead[0] & 0x0f) {
	case WS_TEXT:
	case WS_BINARY:
		p->rxtext = (p->rxhead[0] == WS_TEXT);
		if (p->rxmsg != NULL) {
			ws_pipe_send_close(p, NNG_EPROTO);
			return;
		}
		if (p->rxpaylen > p->rcvmax) {
			ws_pipe_send_close(p, NNG_EMSGSIZE);
			return;
		}
		p->rxstate = WS_RX_PAYLOAD;
		allocsz    = p->rxpaylen;
		if ((p->rxhead[0] & WS_FINAL) == 0) {
			// Allocate message sizes aggressively for fragmented
			// frames to minimize reallocation pain.
			if (allocsz >= WS_FRAGMENT_PREALLOC) {
				allocsz += WS_FRAGMENT_PREALLOC;
			} else {
				allocsz = WS_FRAGMENT_PREALLOC;
			}
		}
		if ((rv = nni_msg_alloc(&p->rxmsg, allocsz)) != 0) {
			ws_pipe_send_close(p, rv);
			return;
		}
		// This cannot fail, because we allocated not less than this.
		(void) nni_msg_realloc(msg, p->rxpaylen);
		p->rxresid = p->rxpaylen;

		// No payload, so just do an empty data receive.
		ws_pipe_recv_cb_payload(p, 0);
		return;

	case WS_CONT: // continuation frame
		if (p->rxmsg == NULL) {
			ws_pipe_send_close(p, NNG_EPROTO);
			return;
		}
		if ((p->rxpaylen + nni_msg_len(p->rxmsg)) > p->rcvmax) {
			ws_pipe_send_close(p, NNG_EMSGSIZE);
			return;
		}

		// It would be nice to be able to check to see if we
		// were going to have to reallocate the underlying
		// memory, and grow a larger chunk if we were, but there
		// is no support for this in the message API.
		rv = nni_msg_realloc(
		    p->rxmsg, p->rxpaylen + nni_msg_len(p->rxmsg));
		if (rv != 0) {
			ws_pipe_send_close(p, rv);
			return;
		}
		p->rxstate = WS_RX_PAYLOAD;
		p->rxresid = p->rxpaylen;
		ws_pipe_recv_cb_payload(p, 0);
		return;

	case WS_CLOSE:
	case WS_PING:
	case WS_PONG:
		// The other side is closing the connection.
		// NNG_ECLOSED.
		p->rxstate = WS_RX_CONTROL;
		p->rxresid = p->rxpaylen;
		if (p->rxresid > 125) {
			rv = NNG_EPROTO;
			break;
		}
		ws_pipe_recv_cb_control(p, 0);
		return;

	default:
		ws_pipe_send_close(p, NNG_EPROTO);
		return;
	}
}

static void
ws_pipe_recv_cb(void *arg)
{
	ws_pipe *p = arg;
	nni_aio *uaio;
	nni_aio *raio;
	size_t   n;
	size_t   need;
	uint8_t  opcode;
	size_t   paylen;
	bool     masked;
	bool     final;

	nni_mtx_lock(&p->mtx);
	if ((uaio = p->user_rxaio) == NULL) {
		// Canceled.
		ws_pipe_send_close(p, NNG_ECANCELED);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	raio = p->rxaio;
	if ((rv = nni_aio_result(raio)) != 0) {
		ws_pipe_send_close(p, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	n = nni_aio_count(raio);

	switch (p->rxstate) {
	case WS_RX_PAYLOAD:
		ws_pipe_recv_cb_payload(p, n);
		break;
	case WS_RX_CONTROL:
		ws_pipe_recv_cb_control(p, n);
		break;
	case WS_RX_HEADER:
		ws_pipe_recv_cb_header(p, n);
		break;
	case WS_RX_CLOSE:
		break;
	}

	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_recv_cancel(nni_aio *aio, int rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = NULL;
	nni_mtx_unlock(&p->mtx);

	nni_aio_cancel(p->rxaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
ws_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	// For receive, we want to read the mandatory header (16 bits),
	// and then we will schedule a follow up read of the residual
	// part.  However, we want to consume from the residual part
	// that might be left over from the HTTP header read.
	// Outstanding question here: do we just start a forever read,
	// loading the HTTP data, and consuming from it (following the
	// TLS model) or do we issue partial reads.  I suspect that
	// buffering here is preferable, but need to be aware of double
	// buffering done by underlying TLS.

	nni_mtx_lock(&p->mtx);
	if (nni_aio_start(aio, ws_pipe_recv_cancel, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	p->user_rxaio = aio;
	NNI_ASSERT(p->rxmsg == NULL);

	rxaio                   = p->rxaio;
	rxaio->a_iov[0].iov_buf = p->rxbuf;
	rxaio->a_iov[0].iov_len = sizeof(uint16_t);
	p->rxnum                = 0;

	nni_http_read_full(p->http, rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (nni_aio_start(aio, ws_pipe_send_cancel, p) != 0) {
		nni_mtx_unlock(&p->mtx);
	}
	if (p->txstate == WS_TX_CLOSE) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_tx_unlock(p->mtx);
	}
	p->user_txaio = aio;
	p->txmsg      = nni_aio_get_msg(aio);
	nni_aio_set_msg(aio, NULL);
	if (p->txstate == WS_TX_IDLE) {
		ws_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static int
ws_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);

	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
ws_pipe_init(ws_pipe **pipep, ws_ep *ep, void *http)
{
	ws_pipe *p;
	int      rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	// Initialize AIOs.
	if (((rv = nni_aio_init(&p->txaio, ws_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ws_pipe_recv_cb, p)) != 0)) {
		ws_pipe_fini(p);
		return (rv);
	}

	p->mode   = ep->mode;
	p->rcvmax = ep->rcvmax;
	//	p->addr   = ep->addr;
	p->http    = http;
	p->rxstate = WS_RX_HEADER;
	p->txstate = WS_TX_IDLE;

	*pipep = p;
	return (0);
}

static uint16_t
ws_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->rproto);
}

#if 0
static void
ws_pipe_start_client(ws_pipe *p, nni_aio *aio)
{
	int       rv;
	nni_list *hdrs = &p->http_req_headers;
	char      wskey[25];
	char *    uri;
	char *    host;
	char *    line;

	if (nni_aio_start(aio, ws_cancel_nego, p) != 0) {
		return;
	}

	// Set up our random key.
	for (int i = 0; i < 4; i++) {
		uint32_t r        = nni_random();
		p->key[i * 4 + 0] = r & 0xff;
		r >>= 4;
		p->key[i * 4 + 1] = r & 0xff;
		r >>= 4;
		p->key[i * 4 + 2] = r & 0xff;
		r >>= 4;
		p->key[i * 4 + 3] = r & 0xff;
	}
	nni_base64_encode(p->key, 16, wskey, sizeof(wskey));
	wskey[24] = '\0';

	// Construct the request headers.
	//	snprintf(p->txhs_buf, "GET %s HTTP/1.1\r\nHost:
	//%s\r\n", uri,
	// host)
	p->user_negaio = aio;
	NNI_ASSERT(p->nego_state == WS_NEGO_INIT);
	if (((rv = ws_set_header(hdrs, "Host", host)) != 0) ||
	    ((rv = ws_set_header(hdrs, "Connection", "Upgrade")) != 0) ||
	    ((rv = ws_set_header(hdrs, "Upgrade", "websocket")) != 0) ||
	    ((rv = ws_set_header(hdrs, "Sec-WebSocket-Key", wskey)) != 0) ||
	    ((rv = ws_set_header(hdrs, "Sec-WebSocket-Protocol", pro)) != 0) ||
	    ((rv = ws_set_header(hdrs, "Sec-WebSocket-Version", "13")) != 0)) {
		    p->user_negaio = NULL);
		    nni_aio_finish_error(aio, rv);
		    return;
	}
	// XXX: Origin?

	host = p->hst;
	len  = snprintf(NULL, 0, "GET %s HTTP/1.1", p->uri);
	if ((line = nni_alloc(len)) = NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}
	if (ws_sprintf_headers(p->txhs_buf, WS_BUFSIZE, line, hdrs) < 0) {
		nni_free(line, len);
		nni_aio_finish_error(aio, NNG_EINVAL);
		return;
	}

	nni_free(line, len);
	p->txhs_get   = 0;
	p->txhs_put   = strlen(p->txhs_buf);
	p->nego_state = WS_NEGO_SEND_REQUEST;

	ws_pipe_nego(p);
}
#endif

static void
ws_pipe_start(void *arg, nni_aio *aio)
{
	// We don't really have to do anything special here, because
	// we negotiated before pipe creation.
	nni_aio_finish(aio, 0, 0);
}

// We have very different approaches for server and client.
// Servers use the HTTP server framework, and a request methodology.

static void
ws_ep_cancel(nni_aio *aio, int rv)
{
	// If this is a client, we just cancel the outgoing connect
	// request.  If its an accept operation then we can simply
	// unregister from the listener.  As another issue, we may
	// have to free / close the listener if we were the final
	// endpoint there.
}

static int
ws_ep_bind(void *arg)
{
	// This will look for a listener, and start it if not already
	// started. It adds the listener to it.
}

static void
ws_ep_accept(void *arg, nni_aio *aio)
{
	// XXX: endpoint accept.  For this we need to start a listener
	// if one isn't already running.  The listener needs to handle
	// TCP completions by starting up the header negotiation, to
	// determine the actual endpoint.
	// This implies we need a list of endpoint listeners.
	// I'm not sure what to do about, or whether to support at all,
	// the notion of endpoint listeners that only listen on a
	// specific IP address instead of INADDR_ANY.  Probably we want
	// to have the bind address as the lookup key, and to treat
	// INADDR_ANY separately.  Presumably we wil fail to bind() if
	// a conflicting port reservation exists?
}

static void
ws_ep_connect(void *arg, nni_aio *aio)
{
	ws_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	// If we can't start, then its dying and we can't report
	// either.
	if ((rv = nni_aio_start(aio, ws_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	// Start the connection process...
	// XXX: probably we should have the callback for this start the
	// endpoint negotiation.  Endpoint negotiation is a PITA.
	nni_plat_tcp_ep_connect(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ws_ep_setopt_recvmaxsz(void *arg, const void *v, size_t sz)
{
	ws_ep *ep = arg;
	if (ep == NULL) {
		return (nni_chkopt_size(v, sz, 0, NNI_MAXSZ));
	}
	return (nni_setopt_size(&ep->rcvmax, v, sz, 0, NNI_MAXSZ));
}

static int
ws_ep_getopt_recvmaxsz(void *arg, void *v, size_t *szp)
{
	ws_ep *ep = arg;
	return (nni_getopt_size(ep->rcvmax, v, szp));
}

static int
ws_tran_init(void)
{
	nni_mtx_init(&ws_lock);
	NNI_LIST_INIT(&ws_listeners, ws_listener, node);
}

static void
ws_tran_fini(void)
{
	nni_mtx_fini(&ws_lock);
}

static nni_tran_pipe_option ws_pipe_options[] = {
#if 0
	// clang-format off
	{ NNG_OPT_LOCADDR, ws_pipe_getopt_locaddr },
	{ NNG_OPT_REMADDR, ws_pipe_getopt_remaddr },
	// clang-format on
#endif
	// terminate list
	{ NULL, NULL }
};

static nni_tran_pipe ws_pipe_ops = {
	.p_fini    = ws_pipe_fini,
	.p_start   = ws_pipe_start,
	.p_send    = ws_pipe_send,
	.p_recv    = ws_pipe_recv,
	.p_close   = ws_pipe_close,
	.p_peer    = ws_pipe_peer,
	.p_options = ws_pipe_options,
};

static nni_tran_ep_option ws_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_getopt = ws_ep_getopt_recvmaxsz,
	    .eo_setopt = ws_ep_setopt_recvmaxsz,
	},
#if 0
	{
	    .eo_name   = NNG_OPT_LINGER,
	    .eo_getopt = ws_ep_getopt_linger,
	    .eo_setopt = ws_ep_setopt_linger,
	},
#endif
	// terminate list
	{ NULL, NULL, NULL },
};

static void
ws_ep_fini(void *arg)
{
	ws_ep *ep = arg;

	nni_strfree(ep->path);
	nni_strfree(ep->host);
	NNI_FREE_STRUCT(ep);
}

static int
ws_parse_pair(char *pair, char **hostp, char **servp)
{
	char *host, *serv, *end;

	if (pair[0] == '[') {
		host = pair + 1;
		// IP address enclosed ... for IPv6 usually.
		if ((end = strchr(host, ']')) == NULL) {
			return (NNG_EADDRINVAL);
		}
		*end = '\0';
		serv = end + 1;
		if (*serv == ':') {
			serv++;
		} else if (*serv != '\0') {
			return (NNG_EADDRINVAL);
		}
	} else {
		host = pair;
		serv = strchr(host, ':');
		if (serv != NULL) {
			*serv = '\0';
			serv++;
		}
	}
	if ((strlen(host) == 0) || (strcmp(host, "*") == 0)) {
		*hostp = NULL;
	} else {
		*hostp = host;
	}
	if ((serv == NULL) || (strlen(serv) == 0)) {
		*servp = NULL;
	} else {
		*servp = serv;
	}
	return (0);
}

static int
ws_ep_init(void *epp, const char *url, nni_sock *sock, int mode)
{
	ws_ep *      ep;
	char         buf[NNG_MAXADDRLEN + 1];
	char *       host;
	char *       path;
	char *       serv;
	char *       qparams;
	bool         https = false;
	nni_aio *    aio;
	nng_sockaddr sa;

	if (nni_strlcpy(buf, url, sizeof(buf)) >= sizeof(buf)) {
		return (NNG_EADDRINVAL);
	}

	if (strncmp(buf, "ws://", strlen("ws://"))) {
		https = false;
		host  = buf + strlen("ws://");
	} else if (strncmp(buf, "wss://", strlen("wss://"))) {
		https = true;
		host  = buf + strlen("wss://");
		return (NNG_ENOTSUP); // NO TLS support yet.
	} else {
		return (NNG_EADDRINVAL);
	}

	if ((path = strchr(host, '/')) != NULL) {
		*path = '\0';
		path++;
	} else {
		path = "/";
	}
	if ((qparams = strchr(path, '?')) != NULL) {
		// We do not support query parameters.  (A peer client can
		// still send them, we just will ignore them.)
		*qparams = '\0';
	}

	// Empty path is /
	if (path[0] == '\0') {
		path = "/";
	}

	if ((rv = ws_parse_pair(host, &host, &serv)) != 0) {
		return (rv);
	}
	if (serv == NULL) {
		serv = https ? "443" : "80";
	}

	if ((rv = nni_aio_init(aio, NULL, NULL)) != 0) {
		return (rv);
	}
	aio->a_addr = &sa;
	nni_plat_tcp_resolv(host, serv, NNG_AF_UNSPEC,
	    mode == NNI_EP_MODE_DIAL ? false : true, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);
	if (rv != 0) {
		return (rv);
	}

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->mode = mode;
	nni_strlcpy(ep->addr, url, sizeof(ep->addr));

	if ((ep->path = nni_strdup(path)) == NULL) {
		// Full path, may include Query Parameters.
		ws_ep_fini(ep);
		return (NNG_ENOMEM);
	}
	if ((ep->host = nni_strdup(host)) == NULL) {
		ws_ep_fini(ep);
		return (NNG_ENOMEM);
	}

	if (mode == NNI_EP_MODE_DIAL) {
		rv = nni_http_client_init(&ep->client, &sa);
	} else {
		// We actually don't support query parameters, so nuke them.
		// (This is only for registration.  The client can still
		// supply them, and we will match and pass to the handler.)
		ep.handler.h_path        = ep->path;
		ep.handler.h_method      = "GET";
		ep.handler.h_host        = ep->host;
		ep.handler.h_is_upgrader = true;
		ep.handler.h_cb          = ws_ep_handle;
		rv = nni_http_server_init(&ep->server, &sa);
	}

	if (rv != 0) {
		ws_ep_fini(ep);
		return (rv);
	}
}

static nni_tran_ep ws_ep_ops = {
	.ep_init    = ws_ep_init,
	.ep_fini    = ws_ep_fini,
	.ep_connect = ws_ep_connect,
	.ep_bind    = ws_ep_bind,
	.ep_accept  = ws_ep_accept,
	.ep_close   = ws_ep_close,
	.ep_options = ws_ep_options,
};

static nni_tran ws_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "ws",
	.tran_ep      = &ws_ep_ops,
	.tran_pipe    = &ws_pipe_ops,
	.tran_init    = ws_tran_init,
	.tran_fini    = ws_tran_fini,
};

int
nng_ws_register(void)
{
	return (nni_tran_register(&ws_tran));
}
