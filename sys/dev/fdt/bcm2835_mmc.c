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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/malloc.h>

#include <machine/intr.h>
#include <machine/bus.h>
#include <machine/fdt.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/fdt.h>

struct bcm2835_mmc_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	bus_size_t		sc_size;
};

int bcm2835_mmc_match(struct device *, void *, void *);
void bcm2835_mmc_attach(struct device *, struct device *, void *);
int bcm2835_mmc_detach(struct device *, int);
int bcm2835_mmc_activate(struct device *, int);

struct cfattach bcm2835_mmc_ca = {
	sizeof(struct bcm2835_mmc_softc),
	bcm2835_mmc_match,
	bcm2835_mmc_attach,
	bcm2835_mmc_detach,
	bcm2835_mmc_activate,
};

struct cfdriver bcm2835_mmc_cd = {
	NULL, "mmc", DV_DISK
};

int
bcm2835_mmc_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return (OF_is_compatible(faa->fa_node, "brcm,bcm2835-mmc")
		|| OF_is_compatible(faa->fa_node, "brcm,bcm2835-sdhci"));
}

void
bcm2835_mmc_attach(struct device *parent, struct device *self, void *aux)
{
	struct bcm2835_mmc_softc *sc = (struct bcm2835_mmc_softc *)self;
	struct fdt_attach_args *faa = aux;

	if (faa->fa_nreg < 1) {
		printf(": no registers\n");
		return;
	}

	sc->sc_iot = faa->fa_iot;
	sc->sc_size = faa->fa_reg[0].size;
	if (bus_space_map(sc->sc_iot, faa->fa_reg[0].addr, sc->sc_size, 0,
	    &sc->sc_ioh)) {
		printf(": can't map registers\n");
		return;
	}

	printf("\n");
}

int 
bcm2835_mmc_detach(struct device *self, int flags)
{
	struct bcm2835_mmc_softc *sc = (struct bcm2835_mmc_softc *)self;

	bus_space_unmap(sc->sc_iot, sc->sc_ioh, sc->sc_size);
	return 0;
}

int
bcm2835_mmc_activate(struct device *self, int flags)
{
	printf("Sup\n");
	return 0;
}
