/*     $OpenBSD: mmc.c,v 1.0 2019/01/13 23:55:29 neil Exp $ */

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

#ifndef BCM2835_DMAC_H
#define BCM2835_DMAC_H

#define DMAC_CS(n)		(0x00 + (0x100 * (n)))
#define  DMAC_CS_RESET		(1<<31)
#define  DMAC_CS_ABORT		(1<<30)
#define  DMAC_CS_DISDEBUG	(1<<29)
#define  DMAC_CS_WAIT_FOR_OUTSTANDING_WRITES (1<<28)
#define  DMAC_CS_PANIC_PRIORITY	(((1<<24) - 1) ^ (1<<20))
#define  DMAC_CS_PRIORITY	(((1<<20) - 1) ^ (1<<16))
#define  DMAC_CS_ERROR		(1<<8)
#define  DMAC_CS_WAITING_FOR_OUTSTANDING_WRITES (1<<6)
#define  DMAC_CS_DREQ_STOPS_DMA	(1<<5)
#define  DMAC_CS_PAUSED		(1<<4)
#define  DMAC_CS_DREQ		(1<<3)
#define  DMAC_CS_INT		(1<<2)
#define  DMAC_CS_END		(1<<1)
#define  DMAC_CS_ACTIVE		(1<<0)
#define  DMAC_CS_INTMASK	(DMAC_CS_INT|DMAC_CS_END)
#define DMAC_CONBLK_AD(n)	(0x04 + (0x100 * (n)))
#define DMAC_TI(n)		(0x08 + (0x100 * (n)))
#define DMAC_SOURCE_AD(n)	(0x0c + (0x100 * (n)))
#define DMAC_DEST_AD(n)		(0x10 + (0x100 * (n)))
#define DMAC_TXFR_LEN(n)	(0x14 + (0x100 * (n)))
#define DMAC_STRIDE(n)		(0x18 + (0x100 * (n)))
#define DMAC_NEXTCONBK(n)	(0x1c + (0x100 * (n)))
#define DMAC_DEBUG(n)		(0x20 + (0x100 * (n)))
#define  DMAC_DEBUG_LITE	(1<<28)
#define  DMAC_DEBUG_VERSION	(((1<<28) - 1) ^ (1<<25))
#define  DMAC_DEBUG_DMA_STATE	(((1<<25) - 1) ^ (1<<16))
#define  DMAC_DEBUG_DMA_ID	(((1<<16) - 1) ^ (1<<8))
#define  DMAC_DEBUG_OUTSTANDING_WRITES (((1<<8) - 1) ^ (1<<4))
#define  DMAC_DEBUG_READ_ERROR	(1<<2)
#define  DMAC_DEBUG_FIFO_ERROR	(1<<1)
#define  DMAC_DEBUG_READ_LAST_NOT_SET_ERROR (1<<0)

struct bcm2835_dmac_conblk {
	uint32_t	cb_ti;
#define DMAC_TI_NO_WIDE_BURSTS	(1<<26)
#define DMAC_TI_WAITS		(((1<<26) - 1) ^ (1<<21))
#define DMAC_TI_PERMAP		(((1<<21) - 1) ^ (1<<16))
#define	 DMAC_TI_PERMAP_BASE	(1<<16)
#define DMAC_TI_BURST_LENGTH	(((1<<16) - 1) ^ (1<<12))
#define DMAC_TI_SRC_IGNORE	(1<<11)
#define DMAC_TI_SRC_DREQ	(1<<10)
#define DMAC_TI_SRC_WIDTH	(1<<9)
#define DMAC_TI_SRC_INC		(1<<8)
#define DMAC_TI_DEST_IGNORE	(1<<7)
#define DMAC_TI_DEST_DREQ	(1<<6)
#define DMAC_TI_DEST_WIDTH	(1<<5)
#define DMAC_TI_DEST_INC	(1<<4)
#define DMAC_TI_WAIT_RESP	(1<<3)
#define DMAC_TI_TDMODE		(1<<1)
#define DMAC_TI_INTEN		(1<<0)
	uint32_t	cb_source_ad;
	uint32_t	cb_dest_ad;
	uint32_t	cb_txfr_len;
#define DMAC_TXFR_LEN_YLENGTH	(((1<<30) - 1) ^ (1<<16))
#define DMAC_TXFR_LEN_XLENGTH	(((1<<16) - 1) ^ (1<<0))
	uint32_t	cb_stride;
#define DMAC_STRIDE_D_STRIDE	(((1<<32) - 1) ^ (1<<16))
#define DMAC_STRIDE_S_STRIDE	(((1<<16) - 1) ^ (1<<0))
	uint32_t	cb_nextconbk;
	uint32_t	cb_padding[2];
} __packed;

#define DMAC_INT_STATUS		0xfe0
#define DMAC_ENABLE		0xff0

enum bcm2835_dmac_type {
	BCM2835_DMAC_TYPE_NORMAL,
	BCM2835_DMAC_TYPE_LITE
};

struct bcm2835_dmac_channel;

struct bcm2835_dmac_channel *bcm2835_dmac_alloc(enum bcm2835_dmac_type, int,
				void (*)(uint32_t, uint32_t, void *), void *);
void bcm2835_dmac_free(struct bcm2835_dmac_channel *);
void bcm2835_dmac_set_conblk_addr(struct bcm2835_dmac_channel *, bus_addr_t);
int bcm2835_dmac_transfer(struct bcm2835_dmac_channel *);
void bcm2835_dmac_halt(struct bcm2835_dmac_channel *);

#endif /* BCM2835_DMAC_H */
