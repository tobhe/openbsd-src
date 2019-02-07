/*     $OpenBSD: mmc.c,v 1.0 2019/01/13 23:55:29 neil Exp $ */

/* Code based on
 *	$NetBSD: bcm2835_mbox_subr.c,v 1.5 2017/12/10 21:38:26 skrll Exp $
 *	$NetBSD: bcm2835_mbox.c,v 1.13 2018/08/19 09:18:48 rin Exp $
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

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <machine/bus.h>
#include <machine/intr.h>
#include <machine/fdt.h>

#include <dev/ofw/fdt.h>
#include <dev/ofw/openfirm.h>

#include "bcm2835_mbox.h"

#define DEVNAME(sc)   			((sc)->sc_dev.dv_xname)

struct cfdriver bmbox_cd = {
	NULL, "bmbox", DV_DULL
};

struct bmbox_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	bus_dma_tag_t		sc_dmat;
	void			*sc_ih;

	struct mutex		sc_lock;
	struct mutex		sc_intr_lock;
	int			sc_chan[BMBOX_NUM_CHANNELS];
	u_int32_t		sc_mbox[BMBOX_NUM_CHANNELS];
};

static volatile void *attached_sc = NULL;

int bmbox_match(struct device *, void *, void *);
void bmbox_attach(struct device *, struct device *, void *);

struct cfattach bmbox_ca = {
	sizeof(struct bmbox_softc),
	bmbox_match,
	bmbox_attach,
};

u_int32_t bmbox_reg_read(struct bmbox_softc *, int);
void bmbox_reg_write(struct bmbox_softc *, int, u_int32_t);
void bmbox_reg_flush(struct bmbox_softc *, int);
int bmbox_intr(void *);
int bmbox_intr_helper(struct bmbox_softc *, int);

int
bmbox_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return OF_is_compatible(faa->fa_node, "brcm,bcm2835-mbox");
}

void
bmbox_attach(struct device *parent, struct device *self, void *aux)
{
	struct bmbox_softc *sc = (struct bmbox_softc *)self;
	struct fdt_attach_args *faa = aux;
	bus_addr_t addr;
	bus_size_t size;
	
	if (atomic_cas_ptr(&attached_sc, NULL, sc)) {
		printf(": a similar device as already attached\n");
		return;
	}

	mtx_init(&sc->sc_lock, IPL_NONE);
	mtx_init(&sc->sc_intr_lock, IPL_VM);

	sc->sc_iot = faa->fa_iot;

	if (faa->fa_nreg < 1) {
		printf(": no registers\n");
		return;
	}

	addr = faa->fa_reg[0].addr;
	size = faa->fa_reg[0].size;
	if (bus_space_map(sc->sc_iot, addr, size, 0, &sc->sc_ioh)) {
		printf(": can't map registers\n");
		return;
	}

	sc->sc_ih = fdt_intr_establish(faa->fa_node, IPL_VM, bmbox_intr, sc,
			DEVNAME(sc));
	if (sc->sc_ih == NULL) {
		printf(": failed to establish interrupts\n");
		goto clean_bus_space_map;
	}

	/* enable interrupt in hardware */
	bmbox_reg_write(sc, BMBOX_CFG, BMBOX_CFG_DATA_IRQ_EN);

	printf("\n");
	return;

	/*
cancel_interrupts:
	fdt_intr_disestablish(sc->sc_ih);
	*/

clean_bus_space_map:
	bus_space_unmap(sc->sc_iot, sc->sc_ioh, size);
}

u_int32_t
bmbox_reg_read(struct bmbox_softc *sc, int addr)
{
	return bus_space_read_4(sc->sc_iot, sc->sc_ioh, addr);
}

void
bmbox_reg_write(struct bmbox_softc *sc, int addr, u_int32_t val)
{
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, addr, val);
}

void
bmbox_reg_flush(struct bmbox_softc *sc, int flags)
{
	bus_space_barrier(sc->sc_iot, sc->sc_ioh, 0, BMBOX_SIZE, flags);
}

int
bmbox_intr(void *cookie)
{
	struct bmbox_softc *sc = cookie;
	int ret;

	mtx_enter(&sc->sc_intr_lock);
	ret = bmbox_intr_helper(sc, 1);
	mtx_leave(&sc->sc_intr_lock);

	return ret;
}

int
bmbox_intr_helper(struct bmbox_softc *sc, int broadcast)
{
	u_int32_t mbox, chan, data;
	int ret = 0;

	bmbox_reg_flush(sc, BUS_SPACE_BARRIER_READ);

	while (!ISSET(bmbox_reg_read(sc, BMBOX_STATUS), BMBOX_STATUS_EMPTY)) {
		mbox = bmbox_reg_read(sc, BMBOX0_READ);
		
		chan = mbox & BMBOX_CHANNEL_MASK;
		data = mbox & ~BMBOX_CHANNEL_MASK;
		ret = 1;

		if ((sc->sc_mbox[chan] & BMBOX_CHANNEL_MASK) != 0) {
			printf("%s: chan %d overflow\n", DEVNAME(sc), chan);
			continue;
		}

		sc->sc_mbox[chan] = data | BMBOX_CHANNEL_MASK;

		if (broadcast)
			wakeup(&sc->sc_chan[chan]);
	}

	return ret;
}

void
bmbox_read(u_int8_t chan, u_int32_t *data)
{
	struct bmbox_softc *sc;
	u_int32_t mbox, rchan, rdata, status;

	do {
		sc = (struct bmbox_softc *)attached_sc;
	} while (sc != atomic_cas_ptr(&attached_sc, sc, sc));

	KASSERT(sc != NULL);
	KASSERT(chan == (chan & BMBOX_CHANNEL_MASK));

	while (1) {
		bmbox_reg_flush(sc, BUS_SPACE_BARRIER_READ);
		status = bmbox_reg_read(sc, BMBOX0_STATUS);
		if (ISSET(status, BMBOX_STATUS_EMPTY))
			continue;

		mbox = bmbox_reg_read(sc, BMBOX0_READ);

		rchan = mbox & BMBOX_CHANNEL_MASK;
		rdata = mbox & ~BMBOX_CHANNEL_MASK;

		if (rchan == chan) {
			*data = rdata;
			return;
		}
	}
}

void
bmbox_write(u_int8_t chan, u_int32_t data)
{
	struct bmbox_softc *sc;
	u_int32_t rdata;

	do {
		sc = (struct bmbox_softc *)attached_sc;
	} while (sc != atomic_cas_ptr(&attached_sc, sc, sc));

	KASSERT(sc != NULL);
	KASSERT(chan == (chan & BMBOX_CHANNEL_MASK));
	KASSERT(data == (data & ~BMBOX_CHANNEL_MASK));

	while (1) {
		bmbox_reg_flush(sc, BUS_SPACE_BARRIER_READ);
		rdata = bmbox_reg_read(sc, BMBOX0_STATUS);
		if (!ISSET(rdata, BMBOX_STATUS_FULL))
			break;
	}

	bmbox_reg_write(sc, BMBOX1_WRITE, chan | data);
	bmbox_reg_flush(sc, BUS_SPACE_BARRIER_WRITE);
}
