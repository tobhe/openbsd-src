/*	$OpenBSD: bcm2835_cprman.c,v 1.0 2019/02/05 10:52:30 Neil Ashford $	*/

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

struct vb_uart {
	struct vcprop_buffer_hdr	vb_hdr;
	struct vcprop_tag_clockrate	vbt_uartclockrate;
	struct vcprop_tag_clockrate	vbt_vpuclockrate;
	struct vcprop_tag end;
} __aligned(16);

struct vb {
	struct vcprop_buffer_hdr	vb_hdr;
	struct vcprop_tag_fwrev		vbt_fwrev;
	struct vcprop_tag_boardmodel	vbt_boardmodel;
	struct vcprop_tag_boardrev	vbt_boardrev;
	struct vcprop_tag_macaddr	vbt_macaddr;
	struct vcprop_tag_memory	vbt_memory;
	struct vcprop_tag_boardserial	vbt_serial;
	struct vcprop_tag_dmachan	vbt_dmachan;
	struct vcprop_tag_cmdline	vbt_cmdline;
	struct vcprop_tag_clockrate	vbt_emmcclockrate;
	struct vcprop_tag_clockrate	vbt_armclockrate;
	struct vcprop_tag_clockrate	vbt_vpuclockrate;
	struct vcprop_tag end;
} __aligned(16);

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
u_int32_t cprman_get_frequency_uart();
u_int32_t cprman_get_frequency_vpu();
u_int32_t cprman_get_frequency_emmc();

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
	switch (*cells) {
	case CPRMAN_CLOCK_EMMC:
		return cprman_get_frequency_emmc();
	case CPRMAN_CLOCK_VPU:
		return cprman_get_frequency_vpu();
	case CPRMAN_CLOCK_UART:
		return cprman_get_frequency_uart();
	default:
		panic("unsupported clock id %d\n", *cells);
	}
}

static struct vb_uart vb_uart = {
	.vb_hdr = {
		.vpb_len = sizeof(vb_uart),
		.vpb_rcode = VCPROP_PROCESS_REQUEST,
	},
	.vbt_uartclockrate = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
			.vpt_len = VCPROPTAG_LEN(vb_uart.vbt_uartclockrate),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
		.id = VCPROP_CLK_UART
	},
	.vbt_vpuclockrate = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
			.vpt_len = VCPROPTAG_LEN(vb_uart.vbt_vpuclockrate),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
		.id = VCPROP_CLK_CORE
	},
	.end = {
		.vpt_tag = VCPROPTAG_NULL
	}
};


static struct vb vb = {
	.vb_hdr = {
		.vpb_len = sizeof(vb),
		.vpb_rcode = VCPROP_PROCESS_REQUEST,
	},
	.vbt_fwrev = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_FIRMWAREREV,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_fwrev),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_boardmodel = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_BOARDMODEL,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_boardmodel),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_boardrev = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_BOARDREVISION,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_boardrev),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_macaddr = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_MACADDRESS,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_macaddr),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_memory = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_ARMMEMORY,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_memory),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_serial = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_BOARDSERIAL,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_serial),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_dmachan = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_DMACHAN,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_dmachan),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_cmdline = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_CMDLINE,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_cmdline),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
	},
	.vbt_emmcclockrate = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_emmcclockrate),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
		.id = VCPROP_CLK_EMMC
	},
	.vbt_armclockrate = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_armclockrate),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
		.id = VCPROP_CLK_ARM
	},
	.vbt_vpuclockrate = {
		.tag = {
			.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
			.vpt_len = VCPROPTAG_LEN(vb.vbt_vpuclockrate),
			.vpt_rcode = VCPROPTAG_REQUEST
		},
		.id = VCPROP_CLK_CORE
	},
	.end = {
		.vpt_tag = VCPROPTAG_NULL
	}
};

u_int32_t
cprman_get_frequency_uart()
{
	return 0; /* XXX */
}

u_int32_t
cprman_get_frequency_vpu()
{
	printf("<%x:%d>", vb.vbt_vpuclockrate.tag.vpt_rcode, vb.vbt_vpuclockrate.rate);
	cprman_init_vb_wrapper();
	if (vcprop_tag_success_p(&vb.vbt_vpuclockrate.tag))
		return vb.vbt_vpuclockrate.rate;
	printf("<%x:%d>", vb.vbt_vpuclockrate.tag.vpt_rcode, vb.vbt_vpuclockrate.rate);
	return 0;
}

u_int32_t
cprman_get_frequency_emmc()
{
	return 0;
}

void
cprman_init_vb_wrapper(void)
{
	/* 0 at first, 1 during initialization, 2 when done */
	static volatile unsigned int done = 0;

	switch (atomic_cas_uint(&done, 0, 1)) {
	case 0:
		/* value is currently uninitialized, we need to set it up */
		break;
	case 1:
		/* someone else is doing it, wait for them to finish */
		while (2 != atomic_cas_uint(&done, 2, 2))
			tsleep(&done, PPAUSE, "pause", 0);
		/* they're done now */
		return;
	case 2:
		/* its already been done */
		return;
	default:
		panic("cprman invariant violation");
	}

	/* actually initialize the thing here */
	cprman_init_vb();

	/* alert the people in case 1 from before */
	KASSERT(atomic_cas_uint(&done, 1, 2) == 1);
	wakeup(&done);

}

struct {
	int dramblocks;
	struct {
		int address;
		int pages;
	} dram[2];
} bootconfig;

void
cprman_init_vb(void)
{
	int res = 6969;
	unsigned long bcm283x_memorysize;
	pmap_t map;
	vaddr_t virtual;
	paddr_t physical = 0;

	map = pmap_kernel();
	virtual = (vaddr_t)&vb_uart;
	pmap_extract(map, virtual, &physical);

	bmbox_write(BCMMBOX_CHANARM2VC,
	physical);

	bmbox_read(BCMMBOX_CHANARM2VC, &res);
	printf("<vbuart:%d>", res);


	bmbox_write(BCMMBOX_CHANPM, (
#if (NSDHC > 0)
	    (1 << VCPM_POWER_SDCARD) |
#endif
#if (NPLCOM > 0)
	    (1 << VCPM_POWER_UART0) |
#endif
#if (NBCMDWCTWO > 0)
	    (1 << VCPM_POWER_USB) |
#endif
#if (NBSCIIC > 0)
	    (1 << VCPM_POWER_I2C0) | (1 << VCPM_POWER_I2C1) |
	/*  (1 << VCPM_POWER_I2C2) | */
#endif
#if (NBCMSPI > 0)
	    (1 << VCPM_POWER_SPI) |
#endif
	    0) << 4);

	virtual = (vaddr_t)&vb;
	physical = 0;

	pmap_extract(map, virtual, &physical);

	bmbox_write(BCMMBOX_CHANARM2VC, physical);
	bmbox_read(BCMMBOX_CHANARM2VC, &res);
	printf("<vb:%d>", res);

	if (!vcprop_buffer_success_p(&vb.vb_hdr)) {
		bootconfig.dramblocks = 1;
		bootconfig.dram[0].address = 0x0;
		bootconfig.dram[0].pages = atop(128U * 1024 * 1024);
		return;
	}

	struct vcprop_tag_memory *vptp_mem = &vb.vbt_memory;
	if (vcprop_tag_success_p(&vptp_mem->tag)) {
		size_t n = vcprop_tag_resplen(&vptp_mem->tag) /
		    sizeof(struct vcprop_memory);

		bcm283x_memorysize = 0;
		bootconfig.dramblocks = 0;

		for (int i = 0; i < n && i < 2; i++) {
			bootconfig.dram[i].address = vptp_mem->mem[i].base;
			bootconfig.dram[i].pages = atop(vptp_mem->mem[i].size);
			bootconfig.dramblocks++;

			bcm283x_memorysize += vptp_mem->mem[i].size;
		}
	}

#if 0
	if (vcprop_tag_success_p(&vb.vbt_armclockrate.tag))
		curcpu()->ci_data.cpu_cc_freq = vb.vbt_armclockrate.rate;
#endif

#ifdef VERBOSE_INIT_ARM
	if (vcprop_tag_success_p(&vb.vbt_memory.tag))
		printf("%s: memory size  %zu\n", __func__,
		    bcm283x_memorysize);
	if (vcprop_tag_success_p(&vb.vbt_armclockrate.tag))
		printf("%s: arm clock    %d\n", __func__,
		    vb.vbt_armclockrate.rate);
	if (vcprop_tag_success_p(&vb.vbt_fwrev.tag))
		printf("%s: firmware rev %x\n", __func__,
		    vb.vbt_fwrev.rev);
	if (vcprop_tag_success_p(&vb.vbt_boardmodel.tag))
		printf("%s: board model  %x\n", __func__,
		    vb.vbt_boardmodel.model);
	if (vcprop_tag_success_p(&vb.vbt_macaddr.tag))
		printf("%s: mac-address  %llx \n", __func__,
		    vb.vbt_macaddr.addr);
	if (vcprop_tag_success_p(&vb.vbt_boardrev.tag))
		printf("%s: board rev    %x\n", __func__,
		    vb.vbt_boardrev.rev);
	if (vcprop_tag_success_p(&vb.vbt_serial.tag))
		printf("%s: board serial %llx\n", __func__,
		    vb.vbt_serial.sn);
	if (vcprop_tag_success_p(&vb.vbt_dmachan.tag))
		printf("%s: DMA channel mask 0x%08x\n", __func__,
		    vb.vbt_dmachan.mask);

	if (vcprop_tag_success_p(&vb.vbt_cmdline.tag))
		printf("%s: cmdline      %s\n", __func__,
		    vb.vbt_cmdline.cmdline);
#endif

}
