/*	$OpenBSD: bcm2835_cprman.c,v 1.0 2019/02/05 10:52:30 Neil Ashford $	*/

/* Code based on
 * $NetBSD: bcm2835_cprman.c,v 1.2 2018/09/09 07:21:17 aymeric Exp $
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
 * Copyright (c) 2017 Jared D. McNeill <jmcneill@invisible.ca>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/device.h>
#include <sys/systm.h>

#include <machine/bootconfig.h>
#include <machine/fdt.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_clock.h>
#include <dev/ofw/fdt.h>

#include <dev/fdt/bcm2835_mbox.h>
#include <dev/fdt/bcm2835_mbox_vcprop.h>

#include <uvm/uvm.h>

enum {
	CPRMAN_CLOCK_TIMER = 17,
	CPRMAN_CLOCK_UART = 19,
	CPRMAN_CLOCK_VPU = 20,
	CPRMAN_CLOCK_V3D = 21,
	CPRMAN_CLOCK_ISP = 22,
	CPRMAN_CLOCK_H264 = 23,
	CPRMAN_CLOCK_VEC = 24,
	CPRMAN_CLOCK_HSM = 25,
	CPRMAN_CLOCK_SDRAM = 26,
	CPRMAN_CLOCK_TSENS = 27,
	CPRMAN_CLOCK_EMMC = 28,
	CPRMAN_CLOCK_PERIIMAGE = 29,
	CPRMAN_CLOCK_PWM = 30,
	CPRMAN_CLOCK_PCM = 31,
	CPRMAN_NCLOCK
};


struct cprman_softc {
	struct device		sc_dev;
	struct clock_device	sc_cd;

};

int cprman_match(struct device *, void *, void *);
void cprman_attach(struct device *, struct device *, void *);

struct cfattach cprman_ca = {
	sizeof(struct cprman_softc),
	cprman_match,
	cprman_attach,
};

u_int32_t cprman_get_frequency(void *, u_int32_t *);

/* We initialize the vb struct (that happens to contain cprman data in it)
 * lazily. cprman_init_vb will perform the initialization, but should only be
 * called inside of cprman_init_vb_wrapper. This function will ensure that the
 * initialization only happens once.
 */
void cprman_init_vb_wrapper();
void cprman_init_vb();

struct cfdriver cprman_cd = {
	NULL, "cprman", DV_DULL
};

int
cprman_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return OF_is_compatible(faa->fa_node, "brcm,bcm2835-cprman");
}

void
cprman_attach(struct device *parent, struct device *self, void *aux)
{
	struct cprman_softc *sc = (struct cprman_softc *)self;
	struct fdt_attach_args *faa = aux;

	sc->sc_cd.cd_node = faa->fa_node;
	sc->sc_cd.cd_cookie = sc;
	sc->sc_cd.cd_get_frequency = cprman_get_frequency;

	printf("\n");

	clock_register(&sc->sc_cd);
}


u_int32_t
cprman_get_frequency(void *cookie, u_int32_t *cells)
{
	struct request {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_clockrate	vbt_clkrate;
		struct vcprop_tag end;
	} __attribute((aligned(16), packed));

	u_int32_t result;
	struct request req = {
		.vb_hdr = {
			.vpb_len = sizeof(req),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_clkrate = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
				.vpt_len = VCPROPTAG_LEN(req.vbt_clkrate),
				.vpt_rcode = VCPROPTAG_REQUEST
			},
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		}
	};

	switch (cells[0]) {
	case CPRMAN_CLOCK_TIMER:
		break;
	case CPRMAN_CLOCK_UART:
		req.vbt_clkrate.id = VCPROP_CLK_UART;
		break;
	case CPRMAN_CLOCK_VPU:
		req.vbt_clkrate.id = VCPROP_CLK_CORE;
		break;
	case CPRMAN_CLOCK_V3D:
		req.vbt_clkrate.id = VCPROP_CLK_V3D;
		break;
	case CPRMAN_CLOCK_ISP:
		req.vbt_clkrate.id = VCPROP_CLK_ISP;
		break;
	case CPRMAN_CLOCK_H264:
		req.vbt_clkrate.id = VCPROP_CLK_H264;
		break;
	case CPRMAN_CLOCK_VEC:
		break;
	case CPRMAN_CLOCK_HSM:
		break;
	case CPRMAN_CLOCK_SDRAM:
		req.vbt_clkrate.id = VCPROP_CLK_SDRAM;
		break;
	case CPRMAN_CLOCK_TSENS:
		break;
	case CPRMAN_CLOCK_EMMC:
		req.vbt_clkrate.id = VCPROP_CLK_EMMC;
		break;
	case CPRMAN_CLOCK_PERIIMAGE:
		break;
	case CPRMAN_CLOCK_PWM:
		req.vbt_clkrate.id = VCPROP_CLK_PWM;
		break;
	case CPRMAN_CLOCK_PCM:
		break;
	}

	if (req.vbt_clkrate.id == 0) {
		printf("cprman[unknown]: request to unknown clock type %d\n", cells[0]);
		return 0;
	}

	bmbox_post(BCMMBOX_CHANARM2VC, &req, sizeof(req), &result);

	if (vcprop_tag_success_p(&req.vbt_clkrate.tag))
		return req.vbt_clkrate.rate;

	printf("cprman[unknown]: vcprop result %x:%x\n", req.vb_hdr.vpb_rcode, req.vbt_clkrate.tag.vpt_rcode);

	return 0;
}

