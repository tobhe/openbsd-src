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

struct mmc_softc {
	struct device sc_dev;
};

int mmc_match(struct device *, void *, void *);
void mmc_attach(struct device *, struct device *, void *);
int mmc_detach(struct device *, int);
int mmc_activate(struct device *, int);

struct cfattach mmc_ca = {
	sizeof(struct mmc_softc),
	mmc_match,
	mmc_attach,
	mmc_detach,
	mmc_activate,
};

struct cfdriver mmc_cd = {
	NULL, "mmc", DV_DISK
};

int
mmc_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return (OF_is_compatible(faa->fa_node, "brcm,bcm2835-mmc")
			|| OF_is_compatible(faa->fa_node, "brcm,bcm2835-sdhci"));
}

void
mmc_attach(struct device *parent, struct device *self, void *aux)
{
	printf("- hello from Neil's driver\n");
}

int 
mmc_detach(struct device *self, int flags)
{
	printf("Sorry I can't do that, Dave\n");
	return 0;
}

int
mmc_activate(struct device *self, int flags)
{
	printf("Sup\n");
	return 0;
}
