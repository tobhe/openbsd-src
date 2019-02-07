/*     $OpenBSD: mmc.c,v 1.0 2019/01/13 23:55:29 neil Exp $ */

/* Code based on
 * $NetBSD: bcm2835_sdhost.c,v 1.4 2017/12/10 21:38:26 skrll Exp $
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
 * Copyright (c) 2017 Jared McNeill <jmcneill@invisible.ca>
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

#include <sys/types.h>
#include <sys/device.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/task.h>

#include <machine/intr.h>
#include <machine/bus.h>
#include <machine/fdt.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_clock.h>
#include <dev/ofw/fdt.h>

#include <dev/sdmmc/sdmmcreg.h>
#include <dev/sdmmc/sdmmcvar.h>

#include <dev/fdt/bcm2835_dmac.h>

#define	SDCMD		0x00
#define	 SDCMD_NEW	(1 << 15)
#define	 SDCMD_FAIL	(1 << 14)
#define	 SDCMD_BUSY	(1 << 11)
#define	 SDCMD_NORESP	(1 << 10)
#define	 SDCMD_LONGRESP	(1 << 9)
#define	 SDCMD_WRITE	(1 << 7)
#define	 SDCMD_READ	(1 << 6)
#define	SDARG		0x04
#define	SDTOUT		0x08
#define	 SDTOUT_DEFAULT	0xf00000
#define	SDCDIV		0x0c
#define	 SDCDIV_MASK	((1 << 11) - 1)
#define	SDRSP0		0x10
#define	SDRSP1		0x14
#define	SDRSP2		0x18
#define	SDRSP3		0x1c
#define	SDHSTS		0x20
#define	 SDHSTS_BUSY	(1 << 10)
#define	 SDHSTS_BLOCK	(1 << 9)
#define	 SDHSTS_SDIO	(1 << 8)
#define	 SDHSTS_REW_TO	(1 << 7)
#define	 SDHSTS_CMD_TO	(1 << 6)
#define	 SDHSTS_CRC16_E	(1 << 5)
#define	 SDHSTS_CRC7_E	(1 << 4)
#define	 SDHSTS_FIFO_E	(1 << 3)
#define	 SDHSTS_DATA	(1 << 0)
#define	SDVDD		0x30
#define	 SDVDD_POWER	(1 << 0)
#define	SDEDM		0x34
#define	 SDEDM_RD_FIFO	(((1 << 19) - 1) ^ ((1 << 14) - 1))
#define  SDEDM_RD_FIFO_BASE (1 << 14)
#define	 SDEDM_WR_FIFO	(((1 << 14) - 1) ^ ((1 << 9) - 1))
#define  SDEDM_WR_FIFO_BASE (1 << 9)
#define	SDHCFG		0x38
#define	 SDHCFG_BUSY_EN	(1 << 10)
#define	 SDHCFG_BLOCK_EN (1 << 8)
#define	 SDHCFG_SDIO_EN	(1 << 5)
#define	 SDHCFG_DATA_EN	(1 << 4)
#define	 SDHCFG_SLOW	(1 << 3)
#define	 SDHCFG_WIDE_EXT (1 << 2)
#define	 SDHCFG_WIDE_INT (1 << 1)
#define	 SDHCFG_REL_CMD	(1 << 0)
#define	SDHBCT		0x3c
#define	SDDATA		0x40
#define	SDHBLC		0x50

struct bsdhost_softc {
	/* device */
	struct device		sc_dev;

	/* interrupts */
	void			*sc_ih;

	/* registers */
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	bus_addr_t		sc_addr;
	bus_size_t		sc_size;

	/* direct memory access */
	bus_dma_tag_t		sc_dmat;
	bus_dmamap_t		sc_dmamap;
	bus_dma_segment_t	sc_segs[1];
	struct bdmac_conblk	*sc_cblk;
	struct bdmac_channel	*sc_dmac;

	/* synchronisation control */
	struct mutex		sc_intr_lock;
	u_int32_t		sc_intr_hsts;
	u_int32_t		sc_intr_cv;
	u_int32_t		sc_dma_cv;


	/* data transfer stats */
	u_int			sc_rate;
	uint32_t		sc_div; /* XXX */

	int			sc_mmc_width;
	int			sc_mmc_presnt;

	u_int32_t		sc_dma_status;
	u_int32_t		sc_dma_error;

	/* attached child driver */
	struct task		sc_attach;
	struct device		*sc_sdmmc;

};

/* general driver functions */
int bsdhost_match(struct device *, void *, void *);
void bsdhost_attach(struct device *, struct device *, void *);
int bsdhost_detach(struct device *, int);

struct cfattach bsdhost_ca = {
	sizeof(struct bsdhost_softc),
	bsdhost_match,
	bsdhost_attach,
	bsdhost_detach,
};

void bsdhost_attach_sdmmc(void *);

/* sdmmc driver functions */
int bsdhost_host_reset(sdmmc_chipset_handle_t);
u_int32_t bsdhost_host_ocr(sdmmc_chipset_handle_t);
int bsdhost_host_maxblklen(sdmmc_chipset_handle_t);
int bsdhost_card_detect(sdmmc_chipset_handle_t);
int bsdhost_bus_power(sdmmc_chipset_handle_t, u_int32_t);
int bsdhost_bus_clock(sdmmc_chipset_handle_t, int, int);
int bsdhost_bus_width(sdmmc_chipset_handle_t, int);
void bsdhost_exec_command(sdmmc_chipset_handle_t, struct sdmmc_command *);

struct sdmmc_chip_functions bsdhost_chip_functions = {
	.host_reset = bsdhost_host_reset,
	.host_ocr = bsdhost_host_ocr,
	.host_maxblklen = bsdhost_host_maxblklen,
	.card_detect = bsdhost_card_detect,
	.bus_power = bsdhost_bus_power,
	.bus_clock = bsdhost_bus_clock,
	.bus_width = bsdhost_bus_width,
	.exec_command = bsdhost_exec_command,
};

/* driver logic */
int bsdhost_wait_idle(struct bsdhost_softc *sc, int timeout);
int bsdhost_dma_wait(struct bsdhost_softc *, struct sdmmc_command *);
int bsdhost_dma_transfer(struct bsdhost_softc *, struct sdmmc_command *);
void bsdhost_dma_done(u_int32_t, u_int32_t, void *);
void bsdhost_write(struct bsdhost_softc *, bus_size_t, u_int32_t);
u_int32_t bsdhost_read(struct bsdhost_softc *, bus_size_t);
int bsdhost_intr(void *);

struct cfdriver bsdhost_cd = {
	NULL, "bsdhost", DV_DISK
};

int
bsdhost_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return OF_is_compatible(faa->fa_node, "brcm,bcm2835-sdhost");
}

void
bsdhost_attach(struct device *parent, struct device *self, void *aux)
{
	struct bsdhost_softc *sc = (struct bsdhost_softc *)self;
	struct fdt_attach_args *faa = aux;
	int rseg;

	/* setup synchronisation primitives */
	mtx_init(&sc->sc_intr_lock, IPL_BIO);

	/* load registers */
	if (faa->fa_nreg < 1) {
		printf(": no registers\n");
		return;
	}

	sc->sc_iot = faa->fa_iot;
	sc->sc_size = faa->fa_reg[0].size;
	sc->sc_addr = faa->fa_reg[0].addr;
	if (bus_space_map(sc->sc_iot, sc->sc_addr, sc->sc_size, 0,
	    &sc->sc_ioh)) {
		printf(": can't map registers\n");
		return;
	}

	sc->sc_div = bsdhost_read(sc, SDCDIV);

	/* check disabled XXX */

	/* enable clocks */
	clock_enable_all(faa->fa_node);
	sc->sc_rate = clock_get_frequency_idx(faa->fa_node, 0);

	/* load DMA */
	sc->sc_dmac = bdmac_alloc(BDMAC_TYPE_NORMAL, IPL_SDMMC,
					 bsdhost_dma_done, sc);
	if (sc->sc_dmac == NULL) {
		printf(": can't open dmac\n");
		goto clean_clocks;
	}

	sc->sc_dmat = faa->fa_dmat;
	if (bus_dmamem_alloc(sc->sc_dmat, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE,
			     sc->sc_segs, 1, &rseg, BUS_DMA_WAITOK)) {
		printf(": can't allocate dmamap\n");
		goto clean_dmac_channel;
	}

	if (bus_dmamem_map(sc->sc_dmat, sc->sc_segs, rseg, PAGE_SIZE,
			   (char **)&sc->sc_cblk, BUS_DMA_WAITOK)) {
		printf(": can't map bus\n");
		goto clean_dmamap_free;
	}

	memset(sc->sc_cblk, 0, PAGE_SIZE);

	if (bus_dmamap_create(sc->sc_dmat, PAGE_SIZE, 1, PAGE_SIZE, 0,
	    BUS_DMA_WAITOK, &sc->sc_dmamap)) {
		printf(": can't map bus\n");
		goto clean_dmamap_unmap;
	}

	if (bus_dmamap_load(sc->sc_dmat, sc->sc_dmamap, sc->sc_cblk,
			    PAGE_SIZE, NULL, BUS_DMA_WAITOK | BUS_DMA_WRITE)) {
		printf(": can't load mapped bus\n");
		goto clean_dmamap_destroy;
	}

	/* enable interrupts */
	sc->sc_ih = fdt_intr_establish(faa->fa_node, IPL_SDMMC, bsdhost_intr,
				       sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": can't establish interrupt\n");
		goto clean_dmamap;
	}

	/* attach the parent driver */
	printf(": %uHz %08x\n", sc->sc_rate, sc->sc_div);

	task_set(&sc->sc_attach, bsdhost_attach_sdmmc, sc);
	task_add(systq, &sc->sc_attach);

	return;

clean_dmamap:
	bus_dmamap_unload(sc->sc_dmat, sc->sc_dmamap);
clean_dmamap_destroy:
	bus_dmamap_destroy(sc->sc_dmat, sc->sc_dmamap);
clean_dmamap_unmap:
	bus_dmamem_unmap(sc->sc_dmat, (void *)sc->sc_cblk, PAGE_SIZE);
clean_dmamap_free:
	bus_dmamem_free(sc->sc_dmat, sc->sc_segs, 1);
clean_dmac_channel:
	bdmac_free(sc->sc_dmac);
clean_clocks:
	clock_disable_all(faa->fa_node);
	bus_space_unmap(sc->sc_iot, sc->sc_ioh, sc->sc_size);
}

void
bsdhost_attach_sdmmc(void *arg)
{
	struct bsdhost_softc *sc = arg;
	struct sdmmcbus_attach_args saa;

	bsdhost_write(sc, SDHCFG, SDHCFG_BUSY_EN);
	bsdhost_bus_clock(sc, 400, false);
	bsdhost_host_reset(sc);
	bsdhost_bus_width(sc, 1);

	memset(&saa, 0, sizeof(saa));
	saa.saa_busname = "sdmmc";
	saa.sct = &bsdhost_chip_functions;
	saa.sch = sc;
	saa.dmat = sc->sc_dmat;
	saa.flags = SMF_SD_MODE /*| SMF_MEM_MODE*/;
	saa.caps = SMC_CAPS_DMA |
	    SMC_CAPS_MULTI_SEG_DMA |
	    SMC_CAPS_SD_HIGHSPEED |
	    SMC_CAPS_MMC_HIGHSPEED |
	    SMC_CAPS_4BIT_MODE;

	sc->sc_sdmmc = config_found(&sc->sc_dev, &saa, NULL);
}

int 
bsdhost_detach(struct device *self, int flags)
{
	struct bsdhost_softc *sc = (struct bsdhost_softc *)self;

	// XXX
	bus_dmamap_unload(sc->sc_dmat, sc->sc_dmamap);
	bus_dmamap_destroy(sc->sc_dmat, sc->sc_dmamap);
	bus_dmamem_unmap(sc->sc_dmat, (void *)sc->sc_cblk, PAGE_SIZE);
	bus_dmamem_free(sc->sc_dmat, sc->sc_segs, 1);
	bus_space_unmap(sc->sc_iot, sc->sc_ioh, sc->sc_size);

	return 0;
}


int
bsdhost_host_reset(sdmmc_chipset_handle_t sch)
{
	struct bsdhost_softc *sc = sch;
	u_int32_t edm;

	bsdhost_write(sc, SDVDD, 0);
	bsdhost_write(sc, SDCMD, 0);
	bsdhost_write(sc, SDARG, 0);
	bsdhost_write(sc, SDTOUT, SDTOUT_DEFAULT);
	bsdhost_write(sc, SDCDIV, 0);
	bsdhost_write(sc, SDHSTS, bsdhost_read(sc, SDHSTS));
	bsdhost_write(sc, SDHCFG, 0);
	bsdhost_write(sc, SDHBCT, 0);
	bsdhost_write(sc, SDHBLC, 0);

	edm = bsdhost_read(sc, SDEDM);
	edm &= ~(SDEDM_RD_FIFO | SDEDM_WR_FIFO);
	edm |= 4 * SDEDM_RD_FIFO_BASE;
	edm |= 4 * SDEDM_WR_FIFO_BASE;
	bsdhost_write(sc, SDEDM, edm);

	delay(20000);
	bsdhost_write(sc, SDVDD, SDVDD_POWER);
	delay(20000);

	bsdhost_write(sc, SDHCFG, bsdhost_read(sc, SDHCFG));
	bsdhost_write(sc, SDCDIV, bsdhost_read(sc, SDCDIV));

	return 0;
}

u_int32_t
bsdhost_host_ocr(sdmmc_chipset_handle_t sch)
{
	return MMC_OCR_3_2V_3_3V | MMC_OCR_3_3V_3_4V | MMC_OCR_HCS;
}

int
bsdhost_host_maxblklen(sdmmc_chipset_handle_t sch)
{
	return 8192;
}

int
bsdhost_card_detect(sdmmc_chipset_handle_t sch)
{
	return 1; /* XXX */
}

int
bsdhost_bus_power(sdmmc_chipset_handle_t sch, u_int32_t ocr)
{
	return 0;
}

int
bsdhost_bus_clock(sdmmc_chipset_handle_t sch, int freq, int ddr)
{
	struct bsdhost_softc *sc = sch;
	u_int target_rate = freq * 1000;
	int div;

	if (freq == 0)
		div = SDCDIV_MASK;
	else {
		div = sc->sc_rate / target_rate;
		if (div < 2)
			div = 2;
		if ((sc->sc_rate / div) > target_rate)
			div++;
		div -= 2;
		if (div > SDCDIV_MASK)
			div = SDCDIV_MASK;
	}

	sc->sc_div = div;
	bsdhost_write(sc, SDCDIV, sc->sc_div);

	return 0;
}

int
bsdhost_bus_width(sdmmc_chipset_handle_t sch, int width)
{
	struct bsdhost_softc *sc = sch;
	u_int32_t hcfg;

	hcfg = bsdhost_read(sc, SDHCFG);
	if (width == 4)
		hcfg |= SDHCFG_WIDE_EXT;
	else
		hcfg &= ~SDHCFG_WIDE_EXT;
	hcfg |= (SDHCFG_WIDE_INT | SDHCFG_SLOW);
	bsdhost_write(sc, SDHCFG, hcfg);

	return 0;
}

void
bsdhost_exec_command(sdmmc_chipset_handle_t sch, struct sdmmc_command *cmd)
{
	struct bsdhost_softc *sc = sch;
	u_int32_t cmdval, hcfg;
	u_int nblks;
	unsigned int line = 0;
#if 0
	printf("%s: %s op %u data %p len %u dmap %p\n", DEVNAME(sc), __func__,
	    cmd->c_opcode, cmd->c_data, cmd->c_datalen, cmd->c_dmamap);
#endif

	mtx_enter(&sc->sc_intr_lock);

	hcfg = bsdhost_read(sc, SDHCFG);
	bsdhost_write(sc, SDHCFG, hcfg | SDHCFG_BUSY_EN);

	sc->sc_intr_hsts = 0;

	cmd->c_error = bsdhost_wait_idle(sc, 5000);
	if (cmd->c_error != 0) // device busy
		goto done;

	cmdval = SDCMD_NEW;
	if (!ISSET(cmd->c_flags, SCF_RSP_PRESENT))
		cmdval |= SDCMD_NORESP;
	if (ISSET(cmd->c_flags, SCF_RSP_136))
		cmdval |= SDCMD_LONGRESP;
	if (ISSET(cmd->c_flags, SCF_RSP_BSY))
		cmdval |= SDCMD_BUSY;

	if (cmd->c_datalen > 0) {
		if (ISSET(cmd->c_flags, SCF_CMD_READ))
			cmdval |= SDCMD_READ;
		else
			cmdval |= SDCMD_WRITE;

		nblks = cmd->c_datalen / cmd->c_blklen;
		if (nblks == 0 || (cmd->c_datalen % cmd->c_blklen) != 0)
			++nblks;

		bsdhost_write(sc, SDHBCT, cmd->c_blklen);
		bsdhost_write(sc, SDHBLC, nblks);

		cmd->c_resid = cmd->c_datalen;
		cmd->c_error = bsdhost_dma_transfer(sc, cmd);
		if (cmd->c_error != 0) { line = __LINE__;
			goto done;
		}
	}

	bsdhost_write(sc, SDARG, cmd->c_arg);
	bsdhost_write(sc, SDCMD, cmdval | cmd->c_opcode);

	if (cmd->c_datalen > 0) {
		cmd->c_error = bsdhost_dma_wait(sc, cmd);
		if (cmd->c_error != 0) { line = __LINE__;
			goto done;
		}
	}

	cmd->c_error = bsdhost_wait_idle(sc, 5000);
	if (cmd->c_error != 0) { line = __LINE__;
		goto done;
	}

	if (ISSET(bsdhost_read(sc, SDCMD), SDCMD_FAIL)) { line = __LINE__;
		cmd->c_error = EIO;
		goto done;
	}

	if (ISSET(cmd->c_flags, SCF_RSP_PRESENT)) {
		if (ISSET(cmd->c_flags, SCF_RSP_136)) {
			cmd->c_resp[0] = bsdhost_read(sc, SDRSP0);
			cmd->c_resp[1] = bsdhost_read(sc, SDRSP1);
			cmd->c_resp[2] = bsdhost_read(sc, SDRSP2);
			cmd->c_resp[3] = bsdhost_read(sc, SDRSP3);
			if (ISSET(cmd->c_flags, SCF_RSP_CRC)) {
				cmd->c_resp[0] = (cmd->c_resp[0] >> 8) |
					(cmd->c_resp[1] << 24);
				cmd->c_resp[1] = (cmd->c_resp[1] >> 8) |
					(cmd->c_resp[2] << 24);
				cmd->c_resp[2] = (cmd->c_resp[2] >> 8) |
					(cmd->c_resp[3] << 24);
				cmd->c_resp[3] = (cmd->c_resp[3] >> 8);
			}
		} else {
			cmd->c_resp[0] = bsdhost_read(sc, SDRSP0);
		}
	}

done:
	cmd->c_flags |= SCF_ITSDONE;
	bsdhost_write(sc, SDHCFG, hcfg);
	bsdhost_write(sc, SDHSTS, bsdhost_read(sc, SDHSTS));
	mtx_leave(&sc->sc_intr_lock);

	if (cmd->c_error) {
		printf("%s: line %u, command %d error %d\n", DEVNAME(sc), line,
		    cmd->c_opcode, cmd->c_error);
	}
}

int
bsdhost_wait_idle(struct bsdhost_softc *sc, int timeout)
{
	int retry;

	retry = timeout * 1000;

	while (--retry > 0) {
		const u_int32_t cmd = bsdhost_read(sc, SDCMD);
		if (!ISSET(cmd, SDCMD_NEW))
			return 0;
		delay(1);
	}

	return ETIMEDOUT;
}

int
bsdhost_dma_wait(struct bsdhost_softc *sc, struct sdmmc_command *cmd)
{
	int error = 0;

	while (sc->sc_dma_status == 0 && sc->sc_dma_error == 0) {
		error = msleep(&sc->sc_dma_cv, &sc->sc_intr_lock, PPAUSE, "pause", 50);
		if (error == EWOULDBLOCK) {
			printf("%s: transfer timeout!\n", DEVNAME(sc));
			bdmac_halt(sc->sc_dmac);
			error = ETIMEDOUT;
			goto error;
		}
	}

	if (ISSET(sc->sc_dma_status, DMAC_CS_END)) {
		cmd->c_resid = 0;
		error = 0;
	} else {
		error = EIO;
	}

error:
	bus_dmamap_sync(sc->sc_dmat, sc->sc_dmamap, 0,
			sc->sc_dmamap->dm_mapsize, BUS_DMASYNC_POSTWRITE);

	return error;
}

int
bsdhost_dma_transfer(struct bsdhost_softc *sc, struct sdmmc_command *cmd)
{
	size_t seg;
	int error;

	for (seg = 0; seg < cmd->c_dmamap->dm_nsegs; seg++) {
		if (sizeof(cmd->c_dmamap->dm_segs[seg].ds_addr) >
		    sizeof(sc->sc_cblk[seg].cb_source_ad)) {
			if (cmd->c_dmamap->dm_segs[seg].ds_addr >
			    0xffffffffU)
				return (EFBIG);
		}
		sc->sc_cblk[seg].cb_ti = 13 * DMAC_TI_PERMAP_BASE;
		sc->sc_cblk[seg].cb_txfr_len = cmd->c_dmamap->dm_segs[seg].ds_len;
		const bus_addr_t ad_sddata = sc->sc_addr + SDDATA;

		/*
		 * All transfers are assumed to be multiples of 32 bits
		 */
		KASSERTMSG((sc->sc_cblk[seg].cb_txfr_len & 0x3) == 0,
			    "seg %zu len %d", seg, sc->sc_cblk[seg].cb_txfr_len);
		/* Use 128-bit mode if transfer is a multiple of 16 bytes.  */
		if (ISSET(cmd->c_flags, SCF_CMD_READ)) {
			sc->sc_cblk[seg].cb_ti |= DMAC_TI_DEST_INC;
			if ((sc->sc_cblk[seg].cb_txfr_len & 0xf) == 0)
				sc->sc_cblk[seg].cb_ti |= DMAC_TI_DEST_WIDTH;
			sc->sc_cblk[seg].cb_ti |= DMAC_TI_SRC_DREQ;
			sc->sc_cblk[seg].cb_source_ad = ad_sddata;
			sc->sc_cblk[seg].cb_dest_ad =
				cmd->c_dmamap->dm_segs[seg].ds_addr;
		} else {
			sc->sc_cblk[seg].cb_ti |= DMAC_TI_SRC_INC;
			if ((sc->sc_cblk[seg].cb_txfr_len & 0xf) == 0)
				sc->sc_cblk[seg].cb_ti |= DMAC_TI_SRC_WIDTH;
			sc->sc_cblk[seg].cb_ti |= DMAC_TI_DEST_DREQ;
			sc->sc_cblk[seg].cb_ti |= DMAC_TI_WAIT_RESP;
			sc->sc_cblk[seg].cb_source_ad =
				cmd->c_dmamap->dm_segs[seg].ds_addr;
			sc->sc_cblk[seg].cb_dest_ad = ad_sddata;
		}
		sc->sc_cblk[seg].cb_stride = 0;
		if (seg == cmd->c_dmamap->dm_nsegs - 1) {
			sc->sc_cblk[seg].cb_ti |= DMAC_TI_INTEN;
			sc->sc_cblk[seg].cb_nextconbk = 0;
		} else {
			sc->sc_cblk[seg].cb_nextconbk =
				sc->sc_dmamap->dm_segs[0].ds_addr +
				sizeof(struct bdmac_conblk) * (seg + 1);
		}
		sc->sc_cblk[seg].cb_padding[0] = 0;
		sc->sc_cblk[seg].cb_padding[1] = 0;
	}

	bus_dmamap_sync(sc->sc_dmat, sc->sc_dmamap, 0,
			sc->sc_dmamap->dm_mapsize, BUS_DMASYNC_PREWRITE);

	error = 0;

	sc->sc_dma_status = 0;
	sc->sc_dma_error = 0;

	bdmac_set_conblk_addr(sc->sc_dmac,
				     sc->sc_dmamap->dm_segs[0].ds_addr);
	error = bdmac_transfer(sc->sc_dmac);

	if (error)
		return error;

	return 0;
}

void
bsdhost_dma_done(u_int32_t status, u_int32_t error, void *arg)
{
	struct bsdhost_softc *sc = arg;

	if (status != (DMAC_CS_INT | DMAC_CS_END))
		printf("%s: dma status %#x error %#x\n", DEVNAME(sc), status,
		       error);

	mtx_enter(&sc->sc_intr_lock);

	sc->sc_dma_status = status;
	sc->sc_dma_error = error;
	wakeup(&sc->sc_dma_cv);

	mtx_leave(&sc->sc_intr_lock);
}

void
bsdhost_write(struct bsdhost_softc *sc, bus_size_t offset, u_int32_t value)
{
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, offset, value);
}

u_int32_t
bsdhost_read(struct bsdhost_softc *sc, bus_size_t offset)
{
	return bus_space_read_4(sc->sc_iot, sc->sc_ioh, offset);
}

int
bsdhost_intr(void *priv)
{
	struct bsdhost_softc *sc = priv;

	mtx_enter(&sc->sc_intr_lock);
	const u_int32_t hsts = bsdhost_read(sc, SDHSTS);

	if (hsts) {
		bsdhost_write(sc, SDHSTS, hsts);
		sc->sc_intr_hsts |= hsts;
		wakeup(&sc->sc_intr_cv);
	}
		

	mtx_leave(&sc->sc_intr_lock);

	return hsts ? 1 : 0;
}
