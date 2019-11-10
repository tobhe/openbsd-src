/*	$OpenBSD$	*/
/*
 * Copyright (c) 2019 Tobias Heider <tobhe@openbsd.org>
 * Copyright (c) 2017 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
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
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "dhcp6.h"
#include "dh6client.h"
#include "frontend.h"

#define	ROUTE_SOCKET_BUF_SIZE	16384
#define	ALLDHCP6		"ff02::1:2"

__dead void	 frontend_shutdown(void);
void		 frontend_sig_handler(int, short, void *);
void		 update_iface(uint32_t, char*);
void		 frontend_startup(void);
void		 send_dhcp6(struct imsg_dhcp6 *);
void		 route_receive(int, short, void *);
void		 handle_route_message(struct rt_msghdr *);
void		 dhcpv6_receive(int, short, void *);
int		 get_flags(char *);
int		 get_xflags(char *);
int		 get_hwaddr(char *, struct ether_addr *);

struct sockaddr_in6		*alldhcp6;
struct imsgev			*iev_main;
struct imsgev			*iev_engine;
struct event			 ev_route;
struct msghdr			 sndmhdr;
struct iovec			 sndiov[2];
int				 dhcp6sock = -1, ioctlsock;

struct dhcp6_ev {
	struct event		 ev;
	uint8_t			 answer[1500];
	struct msghdr		 rcvmhdr;
	struct iovec		 rcviov[1];
	struct sockaddr_in6	 from;
} dhcp6ev;

void
frontend_sig_handler(int sig, short event, void *bula)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		frontend_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
frontend(int debug, int verbose)
{
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;
	struct addrinfo		 hints, *res;
	struct sockaddr_in6	 alldhcp6_storage;
	struct in6_pktinfo	*pi;
	struct cmsghdr		*cm;
	size_t			 rcvcmsglen, sndcmsglen;
	int			 error;
	int			 hoplimit = 255;
	uint8_t			*rcvcmsgbuf, *sndcmsgbuf;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pw = getpwnam(DH6CLIENT_USER)) == NULL)
		fatal("getpwnam");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	if ((error = getaddrinfo(ALLDHCP6, "dhcpv6-server", &hints,
	    &res)) != 0)
		fatalx("%s: getaddrinfo: %s ", __func__, gai_strerror(error));

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	dh6client_process = PROC_FRONTEND;
	setproctitle("%s", log_procnames[dh6client_process]);
	log_procinit(log_procnames[dh6client_process]);

	if ((ioctlsock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		fatal("socket");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio unix recvfd route", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup signal handler. */
	signal_set(&ev_sigint, SIGINT, frontend_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, frontend_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the parent process. */
	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_main->ibuf, 3);
	iev_main->handler = frontend_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	rcvcmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	    CMSG_SPACE(sizeof(int));
	if((rcvcmsgbuf = malloc(rcvcmsglen)) == NULL)
		fatal("malloc");

	dhcp6ev.rcviov[0].iov_base = (caddr_t)dhcp6ev.answer;
	dhcp6ev.rcviov[0].iov_len = sizeof(dhcp6ev.answer);
	dhcp6ev.rcvmhdr.msg_name = (caddr_t)&dhcp6ev.from;
	dhcp6ev.rcvmhdr.msg_namelen = sizeof(dhcp6ev.from);
	dhcp6ev.rcvmhdr.msg_iov = dhcp6ev.rcviov;
	dhcp6ev.rcvmhdr.msg_iovlen = 1;
	dhcp6ev.rcvmhdr.msg_control = (caddr_t) rcvcmsgbuf;
	dhcp6ev.rcvmhdr.msg_controllen = rcvcmsglen;

	/* Initialize outgoing message */
	memset(&alldhcp6_storage, 0, sizeof(alldhcp6_storage));
	memcpy(&alldhcp6_storage, res->ai_addr, res->ai_addrlen);
	alldhcp6 = (struct sockaddr_in6 *)&alldhcp6_storage;

	sndcmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	    CMSG_SPACE(sizeof(int));

	if ((sndcmsgbuf = malloc(sndcmsglen)) == NULL)
		fatal("malloc");

	sndmhdr.msg_namelen = sizeof(struct sockaddr_in6);
	sndmhdr.msg_iov = sndiov;
	sndmhdr.msg_iovlen = 1;
	sndmhdr.msg_control = sndcmsgbuf;
	sndmhdr.msg_controllen = sndcmsglen;

	sndmhdr.msg_name = alldhcp6;

	cm = CMSG_FIRSTHDR(&sndmhdr);

	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	pi = (struct in6_pktinfo *)CMSG_DATA(cm);
	memset(&pi->ipi6_addr, 0, sizeof(pi->ipi6_addr));
	pi->ipi6_ifindex = 0;

	cm = CMSG_NXTHDR(&sndmhdr, cm);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_HOPLIMIT;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &hoplimit, sizeof(int));

	event_dispatch();

	frontend_shutdown();
}

__dead void
frontend_shutdown(void)
{
	/* Close pipes. */
	msgbuf_write(&iev_engine->ibuf.w);
	msgbuf_clear(&iev_engine->ibuf.w);
	close(iev_engine->ibuf.fd);
	msgbuf_write(&iev_main->ibuf.w);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	free(iev_engine);
	free(iev_main);

	log_info("frontend exiting");
	exit(0);
}

int
frontend_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data,
	    datalen));
}

int
frontend_imsg_compose_engine(int type, uint32_t peerid, pid_t pid,
    void *data, uint16_t datalen)
{
	return (imsg_compose_event(iev_engine, type, peerid, pid, -1,
	    data, datalen));
}

void
frontend_dispatch_main(int fd, short event, void *bula)
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
			 * Setup pipe and event handler to the engine
			 * process.
			 */
			if (iev_engine)
				fatalx("%s: received unexpected imsg fd "
				    "to frontend", __func__);

			if ((fd = imsg.fd) == -1)
				fatalx("%s: expected to receive imsg fd to "
				   "frontend but didn't receive any",
				   __func__);

			iev_engine = malloc(sizeof(struct imsgev));
			if (iev_engine == NULL)
				fatal(NULL);

			imsg_init(&iev_engine->ibuf, fd);
			iev_engine->handler = frontend_dispatch_engine;
			iev_engine->events = EV_READ;

			event_set(&iev_engine->ev, iev_engine->ibuf.fd,
			iev_engine->events, iev_engine->handler, iev_engine);
			event_add(&iev_engine->ev, NULL);
			break;
		case IMSG_DHCP6SOCK:
			if ((dhcp6sock = imsg.fd) == -1)
				fatalx("%s: expected to receive imsg "
				    "ICMPv6 fd but didn't receive any",
				    __func__);
			event_set(&dhcp6ev.ev, dhcp6sock, EV_READ | EV_PERSIST,
			    dhcpv6_receive, NULL);
			break;
		case IMSG_ROUTESOCK:
			if ((fd = imsg.fd) == -1)
				fatalx("%s: expected to receive imsg "
				    "routesocket fd but didn't receive any",
				    __func__);
			event_set(&ev_route, fd, EV_READ | EV_PERSIST,
			    route_receive, NULL);
			break;
		case IMSG_STARTUP:
			if (pledge("stdio unix route", NULL) == -1)
				fatal("pledge");
			frontend_startup();
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
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
frontend_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct imsg_dhcp6	 dhcp6;
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
		case IMSG_DHCP6:
			if (IMSG_DATA_SIZE(imsg) != sizeof(dhcp6))
				fatalx("%s: IMSG_DHCP6 wrong length: %lu",
				    __func__, IMSG_DATA_SIZE(imsg));
			memcpy(&dhcp6, imsg.data, sizeof(dhcp6));
			send_dhcp6(&dhcp6);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
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
get_flags(char *if_name)
{
	struct ifreq		 ifr;

	(void) strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(ioctlsock, SIOCGIFFLAGS, (caddr_t)&ifr) == -1) {
		log_warn("SIOCGIFFLAGS");
		return -1;
	}
	return ifr.ifr_flags;
}

int
get_xflags(char *if_name)
{
	struct ifreq		 ifr;

	(void) strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(ioctlsock, SIOCGIFXFLAGS, (caddr_t)&ifr) == -1) {
		log_warn("SIOCGIFXFLAGS");
		return -1;
	}
	return ifr.ifr_flags;
}

void
update_iface(uint32_t if_index, char* if_name)
{
	struct imsg_ifinfo	 imsg_ifinfo;
	int			 flags, xflags;

	if ((flags = get_flags(if_name)) == -1 || (xflags =
	    get_xflags(if_name)) == -1)
		return;

	if (!(xflags & IFXF_AUTOCONF6))
		return;

	memset(&imsg_ifinfo, 0, sizeof(imsg_ifinfo));

	imsg_ifinfo.if_index = if_index;
	imsg_ifinfo.running = (flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP |
	    IFF_RUNNING);

	if (get_hwaddr(if_name, &imsg_ifinfo.hw_address) != 0) {
		log_debug("%s: failed to get HW address for iface %s.",
		    __func__, if_name);
		return;
	}

	frontend_imsg_compose_engine(IMSG_UPDATE_IF, 0, 0, &imsg_ifinfo,
	    sizeof(imsg_ifinfo));
}
int
get_hwaddr(char *if_name, struct ether_addr *mac)
{
	struct ifaddrs		*ifap, *ifa;
	struct sockaddr_dl	*sdl;
	int			 ret = -1;

	if (mac == NULL)
		fatal("mac can not be NULL");

	if (getifaddrs(&ifap) != 0)
		fatal("getifaddrs");

	memset(mac, 0, sizeof(*mac));

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(if_name, ifa->ifa_name) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_LINK) {
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_type != IFT_ETHER ||
			    sdl->sdl_alen != ETHER_ADDR_LEN)
				continue;

			memcpy(mac->ether_addr_octet, LLADDR(sdl),
			    ETHER_ADDR_LEN);
			ret = 0;
			goto done;
		}
	}
 done:
	freeifaddrs(ifap);
	return (ret);
}


void
frontend_startup(void)
{
	struct if_nameindex	*ifnidxp, *ifnidx;

	if (!event_initialized(&ev_route))
		fatalx("%s: did not receive a route socket from the main "
		    "process", __func__);

	event_add(&ev_route, NULL);

	if (!event_initialized(&dhcp6ev.ev))
		fatalx("%s: did not receive a dhcp6 socket fd from the main "
		    "process", __func__);

	event_add(&dhcp6ev.ev, NULL);

	if ((ifnidxp = if_nameindex()) == NULL)
		fatalx("if_nameindex");

	frontend_imsg_compose_main(IMSG_STARTUP_DONE, 0, NULL, 0);

	for(ifnidx = ifnidxp; ifnidx->if_index !=0 && ifnidx->if_name != NULL;
	    ifnidx++) {
		update_iface(ifnidx->if_index, ifnidx->if_name);
	}

	if_freenameindex(ifnidxp);
}

void
route_receive(int fd, short events, void *arg)
{
	static uint8_t			 *buf;

	struct rt_msghdr		*rtm;
	ssize_t				 n;

	if (buf == NULL) {
		buf = malloc(ROUTE_SOCKET_BUF_SIZE);
		if (buf == NULL)
			fatal("malloc");
	}
	rtm = (struct rt_msghdr *)buf;
	if ((n = read(fd, buf, ROUTE_SOCKET_BUF_SIZE)) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		log_warn("dispatch_rtmsg: read error");
		return;
	}

	if (n == 0)
		fatal("routing socket closed");

	if (n < (ssize_t)sizeof(rtm->rtm_msglen) || n < rtm->rtm_msglen) {
		log_warnx("partial rtm of %zd in buffer", n);
		return;
	}

	if (rtm->rtm_version != RTM_VERSION)
		return;

	handle_route_message(rtm);
}

void
handle_route_message(struct rt_msghdr *rtm)
{
	struct if_msghdr		*ifm;
	int				 xflags, if_index;
	char				 ifnamebuf[IFNAMSIZ];
	char				*if_name;

	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		if_name = if_indextoname(ifm->ifm_index, ifnamebuf);
		if (if_name == NULL) {
			log_debug("RTM_IFINFO: lost if %d", ifm->ifm_index);
			if_index = ifm->ifm_index;
			frontend_imsg_compose_engine(IMSG_REMOVE_IF, 0, 0,
			    &if_index, sizeof(if_index));
		} else {
			xflags = get_xflags(if_name);
			if (xflags == -1 || !(xflags & IFXF_AUTOCONF6)) {
				log_debug("RTM_IFINFO: %s(%d) no(longer) "
				   "autoconf6", if_name, ifm->ifm_index);
				if_index = ifm->ifm_index;
				frontend_imsg_compose_engine(IMSG_REMOVE_IF, 0,
				    0, &if_index, sizeof(if_index));
			} else {
				update_iface(ifm->ifm_index, if_name);
			}
		}
		break;
	case RTM_NEWADDR:
		ifm = (struct if_msghdr *)rtm;
		if_name = if_indextoname(ifm->ifm_index, ifnamebuf);
		log_debug("RTM_NEWADDR: %s[%u]", if_name, ifm->ifm_index);
		update_iface(ifm->ifm_index, if_name);
		break;
	default:
		log_debug("unexpected RTM: %d", rtm->rtm_type);
		break;
	}

}

void
dhcpv6_receive(int fd, short events, void *arg)
{
	struct imsg_dhcp6	 msg;
	struct in6_pktinfo	*pi = NULL;
	struct cmsghdr		*cm;
	ssize_t			 len;
	int			 if_index = 0;
	char			 ntopbuf[INET6_ADDRSTRLEN], ifnamebuf[IFNAMSIZ];

	if ((len = recvmsg(fd, &dhcp6ev.rcvmhdr, 0)) == -1) {
		log_warn("recvmsg");
		return;
	}

	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&dhcp6ev.rcvmhdr); cm;
	    cm = (struct cmsghdr *)CMSG_NXTHDR(&dhcp6ev.rcvmhdr, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			if_index = pi->ipi6_ifindex;
		}
	}

	if (if_index == 0) {
		log_warnx("failed to get receiving interface");
		return;
	}

	if ((size_t)len > sizeof(msg.packet)) {
		log_warnx("invalid DHCPv6 message with size %ld from %s on %s",
		    len, inet_ntop(AF_INET6, &dhcp6ev.from.sin6_addr,
		    ntopbuf, INET6_ADDRSTRLEN), if_indextoname(if_index,
		    ifnamebuf));
		return;
	}

	msg.if_index = if_index;
	memcpy(&msg.from,  &dhcp6ev.from, sizeof(msg.from));
	msg.len = len;
	memcpy(msg.packet, dhcp6ev.answer, len);

	frontend_imsg_compose_engine(IMSG_DHCP6, 0, 0, &msg, sizeof(msg));
}

void
send_dhcp6(struct imsg_dhcp6 *imsg)
{
	struct in6_pktinfo	*pi;
	struct cmsghdr		*cm;
	ssize_t			 len;
	int			 hoplimit = 255;

	log_info("%s(%u)", __func__, imsg->if_index);

	sndmhdr.msg_name = alldhcp6;
	sndmhdr.msg_iov[0].iov_base = imsg->packet;
	sndmhdr.msg_iov[0].iov_len = imsg->len;

	cm = CMSG_FIRSTHDR(&sndmhdr);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	pi = (struct in6_pktinfo *)CMSG_DATA(cm);
	memset(&pi->ipi6_addr, 0, sizeof(pi->ipi6_addr));
	pi->ipi6_ifindex = imsg->if_index;

	cm = CMSG_NXTHDR(&sndmhdr, cm);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_HOPLIMIT;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &hoplimit, sizeof(int));

	if ((len = sendmsg(dhcp6sock, &sndmhdr, 0)) != imsg->len)
		log_warn("sendmsg %zd", len);
}
