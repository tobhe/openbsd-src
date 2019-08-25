/*	$OpenBSD$	*/
/*
 * Copyright (c) 2019 Tobias Heider <tobhe@openbsd.org>
 * Copyright (c) 2017 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "log.h"
#include "dh6client.h"
#include "engine.h"
#include "dhcp6.h"

enum if_state {
	IF_DOWN,
	IF_DELAY,
	IF_PROBE,
	IF_IDLE,
};

const char* if_state_name[] = {
	"IF_DOWN",
	"IF_DELAY",
	"IF_PROBE",
	"IF_IDLE",
};

struct dh6client_iface {
	LIST_ENTRY(dh6client_iface)	 entries;
	enum if_state			 state;
	struct event			 timer;
	int				 probes;
	uint32_t			 if_index;
	int				 running;
	struct ether_addr		 hw_address;
	struct sockaddr_in6		 ll_address;
	int				 link_state;
	uint32_t			 cur_mtu;
	struct dhcp6_duid		 duid;
};

LIST_HEAD(, dh6client_iface) dh6client_interfaces;

__dead void		 engine_shutdown(void);
void			 engine_sig_handler(int sig, short, void *);
int			 engine_imsg_compose_main(int, pid_t, void *, uint16_t);
void			 engine_dispatch_main(int, short, void *);
void			 engine_dispatch_frontend(int, short, void *);

struct dh6client_iface	*get_dh6client_iface_by_id(uint32_t);
int			 dhcp6_get_duid(struct ether_addr *, uint8_t,
			    struct dhcp6_duid *d);

struct imsgev		*iev_frontend;
struct imsgev		*iev_main;
int64_t			 proposal_id;

void
engine_sig_handler(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		engine_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
engine(int debug, int verbose)
{
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pw = getpwnam(DH6CLIENT_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	dh6client_process = PROC_ENGINE;
	setproctitle("%s", log_procnames[dh6client_process]);
	log_procinit(log_procnames[dh6client_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup signal handler(s). */
	signal_set(&ev_sigint, SIGINT, engine_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, engine_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the main process. */
	if ((iev_main = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal(NULL);

	imsg_init(&iev_main->ibuf, 3);
	iev_main->handler = engine_dispatch_main;

	/* Setup event handlers. */
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	LIST_INIT(&dh6client_interfaces);

	log_info("Starting engine...");
	event_dispatch();
	log_info("Stopping engine...");

	engine_shutdown();
}

__dead void
engine_shutdown(void)
{
	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	free(iev_frontend);
	free(iev_main);

	log_info("engine exiting");
	exit(0);
}

int
engine_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1,
	    data, datalen));
}

void
engine_dispatch_main(int fd, short event, void *bula)
{
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	ssize_t			 n;
	int			 shut = 0;

	log_info("Engine: Recv from main...");

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_SOCKET_IPC:
			/*
			 * Setup pipe and event handler to the frontend
			 * process.
			 */
			if (iev_frontend)
				fatalx("%s: received unexpected imsg fd "
				    "to engine", __func__);

			if ((fd = imsg.fd) == -1)
				fatalx("%s: expected to receive imsg fd to "
				   "engine but didn't receive any", __func__);

			iev_frontend = malloc(sizeof(struct imsgev));
			if (iev_frontend == NULL)
				fatal(NULL);

			imsg_init(&iev_frontend->ibuf, fd);
			iev_frontend->handler = engine_dispatch_frontend;
			iev_frontend->events = EV_READ;

			event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
			iev_frontend->events, iev_frontend->handler,
			    iev_frontend);
			event_add(&iev_frontend->ev, NULL);

			if (pledge("stdio", NULL) == -1)
				fatal("pledge");
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
engine_imsg_compose_frontend(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_frontend, type, 0, pid, -1,
	    data, datalen));
}

void
engine_dispatch_frontend(int fd, short event, void *bula)
{
	struct dh6client_iface	*iface;
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg_dhcp6	 dhcp6;
	struct imsg_ifinfo	 imsg_ifinfo;
	ssize_t			 n;
	int			 shut = 0;

	log_info("Engine: Recv from frontend...");

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_DHCP6:
			if (IMSG_DATA_SIZE(imsg) != sizeof(dhcp6))
				fatalx("%s: IMSG_DHCP6 wrong length: %lu",
				    __func__, IMSG_DATA_SIZE(imsg));
			memcpy(&dhcp6, imsg.data, sizeof(dhcp6));
			break;
		case IMSG_UPDATE_IF:
			if (IMSG_DATA_SIZE(imsg) != sizeof(imsg_ifinfo))
				fatalx("%s: IMSG_UPDATE_IF wrong length: %lu",
				    __func__, IMSG_DATA_SIZE(imsg));
			memcpy(&imsg_ifinfo, imsg.data, sizeof(imsg_ifinfo));

			iface = get_dh6client_iface_by_id(imsg_ifinfo.if_index);
			if (iface == NULL) {
			 	if ((iface = calloc(1, sizeof(*iface))) == NULL)
			 		fatal("calloc");
			if (dhcp6_get_duid(&imsg_ifinfo.hw_address,
			    DHCP6_DUID_TYPE_LLPT, &iface->duid) != 0)
				fatalx("%s: failed to generate DUID.",
				    __func__);

			log_info("%s: Generated DUID for iface %"PRIu32": %.16s",
			    __func__, imsg_ifinfo.if_index, iface->duid.duid_id);
			// 	evtimer_set(&iface->timer, iface_timeout,
			// 	    iface);
			// 	iface->if_index = imsg_ifinfo.if_index;
			// 	iface->running = imsg_ifinfo.running;
			// 	if (iface->running)
			// 		start_probe(iface);
			// 	else
			// 		iface->state = IF_DOWN;
			// 	iface->autoconfprivacy =
			// 	    imsg_ifinfo.autoconfprivacy;
			// 	iface->soii = imsg_ifinfo.soii;
			// 	memcpy(&iface->hw_address,
			// 	    &imsg_ifinfo.hw_address,
			// 	    sizeof(struct ether_addr));
			// 	memcpy(&iface->ll_address,
			// 	    &imsg_ifinfo.ll_address,
			// 	    sizeof(struct sockaddr_in6));
			// 	memcpy(iface->soiikey, imsg_ifinfo.soiikey,
			// 	    sizeof(iface->soiikey));
			// 	LIST_INIT(&iface->radvs);
			// 	LIST_INSERT_HEAD(&slaacd_interfaces,
			// 	    iface, entries);
			// 	LIST_INIT(&iface->addr_proposals);
			// 	LIST_INIT(&iface->dfr_proposals);
			} else {
			// 	int need_refresh = 0;

			// 	if (iface->autoconfprivacy !=
			// 	    imsg_ifinfo.autoconfprivacy) {
			// 		iface->autoconfprivacy =
			// 		    imsg_ifinfo.autoconfprivacy;
			// 		need_refresh = 1;
			// 	}

			// 	if (iface->soii !=
			// 	    imsg_ifinfo.soii) {
			// 		iface->soii =
			// 		    imsg_ifinfo.soii;
			// 		need_refresh = 1;
			// 	}

			// 	if (memcmp(&iface->hw_address,
			// 		    &imsg_ifinfo.hw_address,
			// 		    sizeof(struct ether_addr)) != 0) {
			// 		memcpy(&iface->hw_address,
			// 		    &imsg_ifinfo.hw_address,
			// 		    sizeof(struct ether_addr));
			// 		need_refresh = 1;
			// 	}
			// 	if (memcmp(iface->soiikey,
			// 		    imsg_ifinfo.soiikey,
			// 		    sizeof(iface->soiikey)) != 0) {
			// 		memcpy(iface->soiikey,
			// 		    imsg_ifinfo.soiikey,
			// 		    sizeof(iface->soiikey));
			// 		need_refresh = 1;
			// 	}

			// 	if (iface->state != IF_DOWN &&
			// 	    imsg_ifinfo.running && need_refresh)
			// 		start_probe(iface);

			// 	iface->running = imsg_ifinfo.running;
			// 	if (!iface->running) {
			// 		iface->state = IF_DOWN;
			// 		if (evtimer_pending(&iface->timer,
			// 		    NULL))
			// 			evtimer_del(&iface->timer);
			// 	}

			// 	memcpy(&iface->ll_address,
			// 	    &imsg_ifinfo.ll_address,
			// 	    sizeof(struct sockaddr_in6));
			}
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

struct dh6client_iface*
get_dh6client_iface_by_id(uint32_t if_index)
{
	struct dh6client_iface	*iface;
	LIST_FOREACH (iface, &dh6client_interfaces, entries) {
		if (iface->if_index == if_index)
			return (iface);
	}

	return (NULL);
}

int
dhcp6_get_duid(struct ether_addr *mac,
    uint8_t type, struct dhcp6_duid *duid)
{
	struct dhcp6_duid_llpt		*llpt;
	size_t				 len;
	uint64_t			 t;
	int				 ret = -1;

	switch (type) {
	case  DHCP6_DUID_TYPE_LLPT:
		len = ETHER_ADDR_LEN + sizeof(struct dhcp6_duid_llpt);

		duid->duid_id = calloc(1, len);
		llpt = (struct dhcp6_duid_llpt *)duid->duid_id;

		llpt->llpt_type = htons(1);
		llpt->llpt_hwtype = htons(type);
		t = (uint64_t)(time(NULL) - 946684800);
		llpt->llpt_time = htonl((uint32_t)(t & 0xffffffff));

		memcpy(llpt + 1, &mac->ether_addr_octet, ETHER_ADDR_LEN);

		ret = 0;
		break;
	default:
		log_debug("%s: Unknown type %"PRIu8".", __func__, type);
		break;
	}
	return ret;
}
