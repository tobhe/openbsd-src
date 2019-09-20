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
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "dh6client.h"
#include "dhcp6.h"

#define	MAX_DHCP6_SOLICITATION_DELAY_USEC	1000000
#define	MAX_DHCP6_SOLICITATIONS			3
#define	DHCP6_SOLICITATION_INTERVAL		4

const char* if_state_name[] = {
	"IF_DOWN",
	"IF_DELAY",
	"IF_PROBE",
	"IF_IDLE",
};

__dead static void	 engine_shutdown(void);
static void		 engine_sig_handler(int sig, short, void *);
static int		 engine_imsg_compose_main(int, pid_t, void *, uint16_t);
static void		 engine_dispatch_main(int, short, void *);
static void		 engine_dispatch_frontend(int, short, void *);
static int		 engine_get_duid(char *, struct dhcp6_duid *);

void			 iface_timeout(int, short, void *);
struct dh6client_iface	*get_dh6client_iface_by_id(uint32_t);
int			 dh6client_parse(struct imsg_dhcp6 *);

struct imsgev		*iev_frontend;
struct imsgev		*iev_main;
int64_t			 proposal_id;

static void
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

	if (engine_get_duid(DH6CLIENT_DUID_FILE, &duid) == -1)
		fatal("duid");

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
	signal_set(&ev_sigint, SIGINT, engine_sig_handler, NULL); signal_set(&ev_sigterm, SIGTERM, engine_sig_handler, NULL);
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

	event_dispatch();

	engine_shutdown();
}

__dead static void
engine_shutdown(void)
{
	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	free(iev_frontend);
	free(iev_main);

	exit(0);
}

static int
engine_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1,
	    data, datalen));
}

static void
engine_dispatch_main(int fd, short event, void *bula)
{
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	ssize_t			 n;
	int			 shut = 0;

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

static int
engine_imsg_compose_frontend(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_frontend, type, 0, pid, -1,
	    data, datalen));
}

static void
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
	struct timeval		 tv;

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
			dh6client_parse(&dhcp6);
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
				memcpy(&iface->hw_address, &imsg_ifinfo.hw_address,
				    sizeof(imsg_ifinfo.hw_address));
				iface->if_index = imsg_ifinfo.if_index;
				iface->running = imsg_ifinfo.running;

				evtimer_set(&iface->timer, iface_timeout, iface);

				/* XXX: Always Rapid-Commit */
				iface->options |= DH6CLIENT_IFACE_OPTION_RAPID;

				iface->state = IF_DELAY;
				iface->probes = 0;

				LIST_INSERT_HEAD(&dh6client_interfaces,
				    iface, entries);

				tv.tv_sec = 0;
				tv.tv_usec = arc4random_uniform(MAX_DHCP6_SOLICITATION_DELAY_USEC);
				if (iface->running)
					evtimer_add(&iface->timer, &tv);
				else
					iface->state = IF_DOWN;
			} else {
				int need_refresh = 0;

				if (memcmp(&iface->hw_address,
					    &imsg_ifinfo.hw_address,
					    sizeof(struct ether_addr)) != 0) {
					memcpy(&iface->hw_address,
					    &imsg_ifinfo.hw_address,
					    sizeof(struct ether_addr));
					need_refresh = 1;
				}
			}
			break;
		default:
			if (IMSG_DATA_SIZE(imsg) != sizeof(dhcp6))
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

void
iface_timeout(int fd, short events, void *arg)
{
	struct dh6client_iface	*iface = (struct dh6client_iface *)arg;
	struct timeval		 tv;

	log_debug("%s[%d]: %s", __func__, iface->if_index,
	    if_state_name[iface->state]);

	switch (iface->state) {
		case IF_DELAY:
		case IF_PROBE:
			if (dh6client_send_solicit(iface) == -1) {
				/* XXX: Handle with UPDATE_IF message */
				log_debug("%s: iface %d failed, disabling",
				    __func__, iface->if_index);
				iface->state = IF_IDLE;
			}
			if (++iface->probes >= MAX_DHCP6_SOLICITATIONS)
				iface->state = IF_IDLE;
			else {
				tv.tv_sec = DHCP6_SOLICITATION_INTERVAL;
				tv.tv_usec = arc4random_uniform(1000000);
				evtimer_add(&iface->timer, &tv);
			}
			break;
		case IF_DOWN:
		case IF_IDLE:
		default:
			break;
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
dh6client_send_solicit(struct dh6client_iface *iface)
{
	struct dhcp6_msg	*msg;
	struct imsg_dhcp6	 imsg;
	uint16_t		 time;

	if ((msg = dhcp6_msg_init(DHCP6_MSG_TYPE_SOLICIT)) == NULL)
		return (-1);

	/* Mandatory client ID */
	if (dhcp6_options_add_option(&msg->msg_options, DHCP6_OPTION_CLIENTID,
	    duid.duid_id, duid.duid_len) == -1)
		return (-1);

	/* Mandatory elapsed time option */
	time = 0;
	if (dhcp6_options_add_option(&msg->msg_options, DHCP6_OPTION_ELAPSED_TIME,
	    &time, sizeof(time)) == -1)
		return (-1);

	/* Request Address  */
	if (dhcp6_options_add_iana(&msg->msg_options, 0, 0, 0) == NULL)
		return (-1);

	if (iface->options & DH6CLIENT_IFACE_OPTION_RAPID)
		dhcp6_options_add_option(&msg->msg_options,
		    DHCP6_OPTION_RAPID_COMMIT, NULL, 0);

	if ((imsg.len = dhcp6_msg_serialize(msg, imsg.packet, 1500)) == -1)
		return (-1);

	/* Check correctness by parsing */
	if (dhcp6_msg_parse(imsg.packet, imsg.len) == NULL)
		return (-1);

	if (log_getverbose()) {
		dhcp6_msg_print(msg);
		print_hex(imsg.packet, 0, imsg.len);
	}

	imsg.if_index = iface->if_index;
	engine_imsg_compose_frontend(IMSG_DHCP6, 0,
	    &imsg, sizeof(imsg));
	dhcp6_msg_free(msg);
	return (0);
}

int
dh6client_parse(struct imsg_dhcp6 *dhcp6)
{
	struct dh6client_iface		*iface;
	struct dhcp6_msg		*msg;
	struct dhcp6_option		*opt;
	struct imsg_configure_address	 address;
	struct dhcp6_opt_iaaddr		 iaaddr;
	char				 buffer[INET6_ADDRSTRLEN];
	const char			*ptr;

	iface = get_dh6client_iface_by_id(dhcp6->if_index);
	if (iface == NULL) {
		log_warn("%s: interface unknown.", __func__);
		return (-1);
	}

	if ((msg = dhcp6_msg_parse(dhcp6->packet, dhcp6->len)) == NULL)
		return (-1);

	log_debug("%s: received message on interface %d.", __func__,
	    iface->if_index);
	if (log_getverbose())
		dhcp6_msg_print(msg);

	switch(msg->msg_type) {
	case DHCP6_MSG_TYPE_ADVERTISE:
		if (iface->options & DH6CLIENT_IFACE_OPTION_RAPID) {
			/* Rapid two message handshake */
			if ((opt = dhcp6_options_get_option(&msg->msg_options,
			    DHCP6_OPTION_IANA)) == NULL) {
				log_debug("%s: No IA_NA option included.",
				    __func__);
				return (-1);
			}
			if ((opt = dhcp6_options_get_option(&opt->option_options,
			    DHCP6_OPTION_IAADDR)) == NULL) {
				log_debug("%s: No IA_ADDRESS option included.",
				    __func__);
				return (-1);
			}

			if ((ptr = inet_ntop(AF_INET6, opt->option_data, buffer,
			    sizeof(buffer))) == NULL)
				return (-1);
			log_info("%s: Obtained IA_NA IPv6 address: %s on iface %d",
			    __func__, ptr, iface->if_index);

			/* Configure Address  */
			dhcp6_options_iaaddress_verify(&iaaddr, opt->option_data);

			address.if_index = iface->if_index;
			memset(&address.mask.s6_addr, 0xff, 16);
			address.addr = iaaddr.iaaddr_addr;
			address.pltime = iaaddr.iaaddr_pltime;
			address.vltime = iaaddr.iaaddr_vltime;

			engine_imsg_compose_main(IMSG_CONFIGURE_ADDRESS, 0,
			    &address, sizeof(address));

			iface->state = IF_IDLE;
		} else {
			/* Four message handshake */

		}
		break;
	default:
		log_warn("%s: unknown message type (%d).", __func__,
		    msg->msg_type);
		break;
	}
	return (0);
}


static int
engine_get_duid(char *path, struct dhcp6_duid *id)
{
	FILE			*fp = NULL;
	int			 ret = -1;
	size_t			 r;

	bzero(id, sizeof(*id));

	if ((fp = fopen(path, "r")) == NULL) {
		/* No previous DUID, generate new */
		if (dhcp6_get_duid(NULL, DHCP6_DUID_TYPE_RAND, id) == -1)
			goto err;

		if ((fp = fopen(path, "w+")) == NULL) {
			log_debug("%s: Failed to open DUID for write.",
			    __func__);
			goto err;
		}
		if ((fwrite(&id->duid_len, sizeof(id->duid_len), 1, fp)) != 1) {
			goto err;
		}
		if ((fwrite(id->duid_id, id->duid_len, 1, fp)) != 1) {
			goto err;
		}
	} else {
		if ((r = fread(&id->duid_len, sizeof(id->duid_len), 1, fp))
		    != 1) {
			log_debug("%s: error failed read len:", __func__);
			goto err;
		}

		id->duid_id = calloc(id->duid_len, sizeof(uint8_t));
		if ((r = fread(id->duid_id, 1, id->duid_len, fp))
		    != id->duid_len) {
			log_debug("%s: error failed read:", __func__);
			goto err;
		}
	}
	print_debug("%s: DUID: ", __func__);
	print_hex(id->duid_id, 0, id->duid_len);
	ret = 0;
 err:
	fclose(fp);
	return (ret);
}
