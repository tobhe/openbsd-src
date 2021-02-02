/*	$OpenBSD:$	*/

/*
 * Copyright (c) 2021 Tobias Heider <tobias.heider@stusta.de>
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

#include <sys/ioctl.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>

#include <event.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <iked.h>

#define IKED_VROUTE_PRIO	7

#define ROUNDUP(a)			\
    (((a) & (sizeof(long) - 1)) ? (1 + ((a) | (sizeof(long) - 1))) : (a))

int vroute_setroute(struct iked *, uint8_t, struct sockaddr *, uint8_t,
    struct sockaddr *, int);
int vroute_getroute(struct iked *, struct imsg *, uint8_t, int);
int vroute_doroute(struct iked *, int, int, int, uint8_t, struct sockaddr *,
    struct sockaddr *, struct sockaddr *);
int vroute_doaddr(struct iked *, char *, struct in_addr *, struct in_addr *, int);

struct iked_vroute_sc {
	int	ivr_iosock;
	int	ivr_rtsock;
	int	ivr_rtseq;
	pid_t	ivr_pid;
};

struct vroute_msg {
	struct rt_msghdr	 vm_rtm;
	uint8_t			 vm_space[512];
};

int vroute_process(struct iked *, int msglen, struct vroute_msg *,
    struct sockaddr *, struct sockaddr *, struct sockaddr *);

void
vroute_init(struct iked *env)
{
	struct iked_vroute_sc	*ivr;

	ivr = calloc(1, sizeof(*ivr));
	if (ivr == NULL)
		fatal("%s: calloc.", __func__);

	if ((ivr->ivr_iosock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("%s: failed to create ioctl socket", __func__);

	if ((ivr->ivr_rtsock = socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC)) == -1)
		fatal("%s: failed to create routing socket", __func__);

	ivr->ivr_pid = getpid();

	env->sc_vroute = ivr;
}

int
vroute_getaddr(struct iked *env, struct imsg *imsg)
{
	char			 ifname[IF_NAMESIZE];
	struct sockaddr_in	*addr, *mask;
	uint8_t			*ptr;
	size_t			 left;
	int			 af;
	unsigned int		 ifidx;

	ptr = imsg->data;
	left = IMSG_DATA_SIZE(imsg);
	if (left != sizeof(*addr) + sizeof(*mask) + sizeof(ifidx))
		fatalx("bad length imsg received");

	addr = (struct sockaddr_in *) ptr;
	af = addr->sin_family;
	ptr += sizeof(*addr);
	left -= sizeof(*addr);

	mask = (struct sockaddr_in *) ptr;
	if (mask->sin_family != af)
		return (-1);
	ptr += sizeof(*mask);
	left -= sizeof(*mask);

	memcpy(&ifidx, ptr, sizeof(ifidx));
	ptr += sizeof(ifidx);
	left -= sizeof(ifidx);

	if_indextoname(ifidx, ifname);

	if (imsg->hdr.type == IMSG_IF_ADDADDR)
		return (vroute_addaddr(env, ifname, &addr->sin_addr, &mask->sin_addr));
	else
		return (vroute_deladdr(env, ifname, &addr->sin_addr));
}

int
vroute_setaddroute(struct iked *env, uint8_t rdomain, struct sockaddr *dst,
    uint8_t mask, struct sockaddr *ifa)
{
	return (vroute_setroute(env, rdomain, dst, mask, ifa,
	    IMSG_VROUTE_ADD));
}

int
vroute_setcloneroute(struct iked *env, uint8_t rdomain, struct sockaddr *dst,
    uint8_t mask, struct sockaddr *addr)
{
	return (vroute_setroute(env, rdomain, dst, mask, addr,
	    IMSG_VROUTE_CLONE));
}

int
vroute_setdelroute(struct iked *env, uint8_t rdomain, struct sockaddr *dst,
    uint8_t mask, struct sockaddr *addr)
{
	return (vroute_setroute(env, rdomain, dst, mask, addr,
	    IMSG_VROUTE_DEL));
}

int
vroute_setroute(struct iked *env, uint8_t rdomain, struct sockaddr *dst,
    uint8_t mask, struct sockaddr *addr, int type)
{
	struct sockaddr_storage	 sa;
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;
	struct iovec		 iov[5];
	int			 iovcnt = 0;
	uint8_t			 af;

	if (addr && dst->sa_family != addr->sa_family)
		return (-1);
	af = dst->sa_family;

	iov[iovcnt].iov_base = &af;
	iov[iovcnt].iov_len = sizeof(af);
	iovcnt++;

	iov[iovcnt].iov_base = &rdomain;
	iov[iovcnt].iov_len = sizeof(rdomain);
	iovcnt++;

	iov[iovcnt].iov_base = dst;
	iov[iovcnt].iov_len = dst->sa_len;
	iovcnt++;

	if (type != IMSG_VROUTE_CLONE) {
		bzero(&sa, sizeof(sa));
		switch(af) {
		case AF_INET:
			in = (struct sockaddr_in *)&sa;
			in->sin_addr.s_addr = prefixlen2mask(mask);
			in->sin_family = af;
			in->sin_len = sizeof(*in);
			iov[iovcnt].iov_base = in;
			iov[iovcnt].iov_len = sizeof(*in);
			iovcnt++;
			break;
		case AF_INET6:
			in6 = (struct sockaddr_in6 *)&sa;
			prefixlen2mask6(mask,
			    (uint32_t *)in6->sin6_addr.s6_addr);
			in6->sin6_family = af;
			in6->sin6_len = sizeof(*in6);
			iov[iovcnt].iov_base = in6;
			iov[iovcnt].iov_len = sizeof(*in6);
			iovcnt++;
			break;
		}

		iov[iovcnt].iov_base = addr;
		iov[iovcnt].iov_len = addr->sa_len;
		iovcnt++;
	}

	return (proc_composev(&env->sc_ps, PROC_PARENT, type, iov, iovcnt));
}

int
vroute_getaddroute(struct iked *env, struct imsg *imsg)
{
	return (vroute_getroute(env, imsg, RTM_ADD, RTF_UP | RTF_STATIC));
}

int
vroute_getdelroute(struct iked *env, struct imsg *imsg)
{
	return (vroute_getroute(env, imsg, RTM_DELETE, RTF_STATIC));
}

int
vroute_getroute(struct iked *env, struct imsg *imsg, uint8_t type, int flags)
{
	struct sockaddr		*sa[3];
	uint8_t			*ptr;
	size_t			 left;
	uint8_t			 af, rdomain;
	int			 i;
	int			 addrs;

	ptr = (uint8_t *)imsg->data;
	left = IMSG_DATA_SIZE(imsg);

	if (left < sizeof(af))
		return (-1);
	af = *ptr;
	ptr += sizeof(af);
	left -= sizeof(af);

	if (left < sizeof(rdomain))
		return (-1);
	rdomain = *ptr;
	ptr += sizeof(rdomain);
	left -= sizeof(rdomain);

	for (i = 0; i < 3; i++) {
		switch(af) {
		case AF_INET:
			if (left < sizeof(struct sockaddr_in))
				return (-1);
			sa[i] = (struct sockaddr *)ptr;
			ptr += sizeof(struct sockaddr_in);
			left -= sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			if (left < sizeof(struct sockaddr_in6))
				return (-1);
			sa[i] = (struct sockaddr *)ptr;
			ptr += sizeof(struct sockaddr_in6);
			left -= sizeof(struct sockaddr_in6);
			break;
		default:
			return (-1);
		}
	}
	addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	return (vroute_doroute(env, flags, addrs, rdomain, type,
	    sa[0], sa[1], sa[2]));
}

int
vroute_getcloneroute(struct iked *env, struct imsg *imsg)
{
	struct sockaddr		*dst;
	struct sockaddr_storage	 dest;
	struct sockaddr_storage	 mask;
	struct sockaddr_storage	 addr;
	uint8_t			*ptr;
	size_t			 left;
	uint8_t			 af, rdomain;
	int			 flags;
	int			 addrs;

	log_debug("%s: called.", __func__);

	ptr = (uint8_t *)imsg->data;
	left = IMSG_DATA_SIZE(imsg);

	if (left < sizeof(af))
		return (-1);
	af = *ptr;
	ptr += sizeof(af);
	left -= sizeof(af);

	if (left < sizeof(rdomain))
		return (-1);
	rdomain = *ptr;
	ptr += sizeof(rdomain);
	left -= sizeof(rdomain);

	bzero(&dest, sizeof(dest));
	bzero(&mask, sizeof(mask));
	bzero(&addr, sizeof(addr));

	switch(af) {
	case AF_INET:
		if (left < sizeof(struct sockaddr_in))
			return (-1);
		dst = (struct sockaddr *)ptr;;
		memcpy(&dest, ptr, sizeof(struct sockaddr_in));;
		ptr += sizeof(struct sockaddr_in);
		left -= sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		if (left < sizeof(struct sockaddr_in6))
			return (-1);
		dst = (struct sockaddr *)ptr;;
		memcpy(&dest, ptr, sizeof(struct sockaddr_in6));;
		ptr += sizeof(struct sockaddr_in6);
		left -= sizeof(struct sockaddr_in6);
		break;
	default:
		return (-1);
	}

	/* Get route to peer */
	flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC;
	if (vroute_doroute(env, flags, RTA_DST, rdomain, RTM_GET,
	    (struct sockaddr *)&dest, (struct sockaddr *)&mask,
	    (struct sockaddr *)&addr))
		return (-1);

	/* Set explicit route to peer with gateway addr*/
	addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	return (vroute_doroute(env, flags, addrs, rdomain, RTM_ADD,
	    dst, (struct sockaddr *)&mask, (struct sockaddr *)&addr));
}

int
vroute_doroute(struct iked *env, int flags, int addrs, int rdomain, uint8_t type,
    struct sockaddr *dest, struct sockaddr *mask, struct sockaddr *addr)
{
	struct vroute_msg	 m_rtmsg;
	char			 destbuf[INET_ADDRSTRLEN];
	char			 maskbuf[INET_ADDRSTRLEN];
	char			 gwbuf[INET_ADDRSTRLEN];
	struct iovec		 iov[7];
	struct iked_vroute_sc	*ivr = env->sc_vroute;
	struct sockaddr_in	*in;
	ssize_t			 len;
	int			 iovcnt = 0;
	int			 i;
	long			 pad = 0;
	size_t			 padlen;

	bzero(&m_rtmsg, sizeof(m_rtmsg));
#define rtm m_rtmsg.vm_rtm
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_tableid = rdomain;
	rtm.rtm_type = type;
	rtm.rtm_seq = ++ivr->ivr_rtseq;
	/* XXX: Pass as arg ?*/
	if (type != RTM_GET)
		rtm.rtm_priority = IKED_VROUTE_PRIO;
	rtm.rtm_flags = flags;
	rtm.rtm_addrs = addrs;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt].iov_len = sizeof(rtm);
	iovcnt++;

	if (rtm.rtm_addrs & RTA_DST) {
		in = (struct sockaddr_in *)dest;
		strlcpy(destbuf, inet_ntoa(in->sin_addr), sizeof(destbuf));
		iov[iovcnt].iov_base = dest;
		iov[iovcnt].iov_len = dest->sa_len;
		iovcnt++;
		padlen = ROUNDUP(dest->sa_len) - dest->sa_len;
		if (padlen > 0) {
			iov[iovcnt].iov_base = &pad;
			iov[iovcnt].iov_len = padlen;
			iovcnt++;
		}
	}

	if (rtm.rtm_addrs & RTA_GATEWAY) {
		in = (struct sockaddr_in *)addr;
		strlcpy(gwbuf, inet_ntoa(in->sin_addr), sizeof(gwbuf));
		iov[iovcnt].iov_base = addr;
		iov[iovcnt].iov_len = addr->sa_len;
		iovcnt++;
		padlen = ROUNDUP(addr->sa_len) - addr->sa_len;
		if (padlen > 0) {
			iov[iovcnt].iov_base = &pad;
			iov[iovcnt].iov_len = padlen;
			iovcnt++;
		}
	}

	if (rtm.rtm_addrs & RTA_NETMASK) {
		in = (struct sockaddr_in *)mask;
		strlcpy(maskbuf, inet_ntoa(in->sin_addr), sizeof(maskbuf));
		iov[iovcnt].iov_base = mask;
		iov[iovcnt].iov_len = mask->sa_len;
		iovcnt++;
		padlen = ROUNDUP(mask->sa_len) - mask->sa_len;
		if (padlen > 0) {
			iov[iovcnt].iov_base = &pad;
			iov[iovcnt].iov_len = padlen;
			iovcnt++;
		}
	}

	log_debug("%s: len: %u type: %s rdomain: %d dst: %s mask: %s gw: %s", __func__,
	    rtm.rtm_msglen,
	    type == RTM_ADD ? "RTM_ADD" :
	    type == RTM_DELETE ? "RTM_DELETE" :
	    type == RTM_GET ? "RTM_GET" : "unknown",
	    rdomain, destbuf, maskbuf, gwbuf);

	for (i = 0; i < iovcnt; i++)
		rtm.rtm_msglen += iov[i].iov_len;

	if (writev(ivr->ivr_rtsock, iov, iovcnt) == -1) {
		if ((type == RTM_ADD && errno != EEXIST) ||
		    (type == RTM_DELETE && errno != ESRCH)) {
			log_warn("%s: write %d", __func__, rtm.rtm_errno);
			return (-1);
		}
	}

	if (type == RTM_GET) {
		do {
			len = read(ivr->ivr_rtsock, &m_rtmsg, sizeof(m_rtmsg));
		} while(len > 0 && (rtm.rtm_version != RTM_VERSION ||
		    rtm.rtm_seq != ivr->ivr_rtseq || rtm.rtm_pid != ivr->ivr_pid));
		return (vroute_process(env, len, &m_rtmsg, dest, mask, addr));
	}
#undef rtm

	return (0);
}

int
vroute_process(struct iked *env, int msglen, struct vroute_msg *m_rtmsg,
    struct sockaddr *dest, struct sockaddr *mask, struct sockaddr *addr)
{
	struct sockaddr *sa;
	char *cp;
	int i;

#define rtm m_rtmsg->vm_rtm
	if (rtm.rtm_version != RTM_VERSION) {
		warnx("routing message version %u not understood",
		    rtm.rtm_version);
		return (-1);
	}
	if (rtm.rtm_msglen > msglen) {
		warnx("message length mismatch, in packet %u, returned %d",
		    rtm.rtm_msglen, msglen);
		return (-1);
	}
	if (rtm.rtm_errno) {
		warnx("RTM_GET: %s (errno %d)",
		    strerror(rtm.rtm_errno), rtm.rtm_errno);
		return (-1);
	}
	cp = m_rtmsg->vm_space;
	if(rtm.rtm_addrs) {
		for (i = 1; i; i <<= 1) {
			if (i & rtm.rtm_addrs) {
				/* XXX: IPv6 */
				sa = (struct sockaddr *)cp;
				switch(i) {
				case RTA_DST:
					memcpy(dest, cp, sa->sa_len);
					break;
				case RTA_NETMASK:
					memcpy(mask, cp, sa->sa_len);
					break;
				case RTA_GATEWAY:
					memcpy(addr, cp, sa->sa_len);
					break;
				}
				cp += ROUNDUP(sa->sa_len);
			}
		}
	}
#undef rtm
	return (0);
}

int
vroute_addaddr(struct iked *env, char *ifname, struct in_addr *addr,
    struct in_addr *mask)
{
	return (vroute_doaddr(env, ifname, addr, mask, 1));
}

int
vroute_deladdr(struct iked *env, char *ifname, struct in_addr *addr)
{
	return (vroute_doaddr(env, ifname, addr, NULL, 0));
}

int
vroute_doaddr(struct iked *env, char *ifname, struct in_addr *addr,
    struct in_addr *mask, int add)
{
	struct iked_vroute_sc	*ivr = env->sc_vroute;
	struct ifaliasreq	 req;
	struct sockaddr_in	*in;
	unsigned long		 ioreq;

	bzero(&req, sizeof(req));
	strncpy(req.ifra_name, ifname, sizeof(req.ifra_name));

	in = (struct sockaddr_in *)&req.ifra_addr;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(req.ifra_addr);
	in->sin_addr.s_addr = addr->s_addr;

	if (add) {
		in = (struct sockaddr_in *)&req.ifra_mask;
		in->sin_family = AF_INET;
		in->sin_len = sizeof(req.ifra_mask);
		in->sin_addr.s_addr = mask->s_addr;
	}

	ioreq = add ? SIOCAIFADDR : SIOCDIFADDR;
	if (ioctl(ivr->ivr_iosock, ioreq, &req) == -1) {
		log_warn("%s: req: %lu, %s", __func__, ioreq,
		    inet_ntoa(*addr));
		return (-1);
	}

	return (0);
}
