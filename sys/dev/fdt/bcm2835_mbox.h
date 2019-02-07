/*     $OpenBSD: bcm2835_mbox.h,v 1.0 2019/01/13 23:55:29 neil Exp $ */

/* Code based on
 *	$NetBSD: bcm2835_mbox.h,v 1.5 2014/10/07 08:30:05 skrll Exp $
 */

/*
 * Copyright (c) 2019 Neil Ashford <ashfordneil0@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Copyright (c) 2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Nick Hudson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef BMBOX_H
#define BMBOX_H

#define BMBOX_NUM_CHANNELS 16
#define BMBOX_CHANNEL_MASK 0xf

/* mailbox 0 (from VC) and mailbox 1 (to VC) */
#define	BMBOX_SIZE	0x80

#define	BMBOX_READ	0x00
#define	BMBOX_WRITE	0x00
#define	BMBOX_POLL	0x10	/* read without popping the fifo */
#define	BMBOX_ID		0x14	/* sender ID (bottom two bits) */
#define	BMBOX_STATUS	0x18	/* status */
#define	 BMBOX_STATUS_FULL	0x80000000
#define	 BMBOX_STATUS_EMPTY	0x40000000
#define	 BMBOX_STATUS_LEVEL	0x400000FF
#define	BMBOX_CFG	0x1C	/* configuration */
#define	 BMBOX_CFG_DATA_IRQ_EN		0x00000001
#define	 BMBOX_CFG_SPACE_IRQ_EN		0x00000002
#define	 BMBOX_CFG_EMPTYOP_IRQ_EN	0x00000004
#define	 BMBOX_CFG_MAIL_CLEAR		0x00000008
#define	 BMBOX_CFG_DATA_PENDING		0x00000010
#define	 BMBOX_CFG_SPACE_PENDING	0x00000020
#define	 BMBOX_CFG_EMPTY_OP_PENDING	0x00000040
#define	 BMBOX_CFG_E_NO_OWN		0x00000100
#define	 BMBOX_CFG_E_OVERFLOW		0x00000200
#define	 BMBOX_CFG_E_UNDERFLOW		0x00000400

#define	BMBOX0_BASE	0x00
#define	BMBOX1_BASE	0x20

#define	BMBOX0_READ	(BMBOX0_BASE + BMBOX_READ)
#define	BMBOX0_WRITE	(BMBOX0_BASE + BMBOX_WRITE)
#define	BMBOX0_POLL	(BMBOX0_BASE + BMBOX_POLL)
#define	BMBOX0_ID	(BMBOX0_BASE + BMBOX_ID)
#define	BMBOX0_STATUS	(BMBOX0_BASE + BMBOX_STATUS)
#define	BMBOX0_CFG	(BMBOX0_BASE + BMBOX_READ)

#define	BMBOX1_READ	(BMBOX1_BASE + BMBOX_READ)
#define	BMBOX1_WRITE	(BMBOX1_BASE + BMBOX_WRITE)
#define	BMBOX1_POLL	(BMBOX1_BASE + BMBOX_POLL)
#define	BMBOX1_ID	(BMBOX1_BASE + BMBOX_ID)
#define	BMBOX1_STATUS	(BMBOX1_BASE + BMBOX_STATUS)
#define	BMBOX1_CFG	(BMBOX1_BASE + BMBOX_READ)

void bmbox_read(u_int8_t chan, u_int32_t *data);
void bmbox_write(u_int8_t chan, u_int32_t data);

#endif /* BCM2835_DMAC_H */
