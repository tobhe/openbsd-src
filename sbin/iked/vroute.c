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
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <iked.h>

#define IKED_VROUTE_PRIO	7

#define ROUNDUP(a)			\
    (((a) & (sizeof(long) - 1)) ? (1 + ((a) | (sizeof(long) - 1))) : (a))

int vroute_getroute(struct iked *, struct imsg *, uint8_t);
int vroute_doroute(struct iked *, int, uint8_t, struct sockaddr *,
    struct sockaddr *, struct sockaddr *);

struct iked_vroute_sc {
	int	ivr_iosock;
	int	ivr_rtsock;
	int	ivr_rtseq;
};

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

	env->sc_vroute = ivr;
}

int
vroute_setaddroute(struct iked *env, uint8_t rdomain, struct sockaddr *dst,
    uint8_t mask, struct sockaddr *ifa)
{
	struct sockaddr_storage	 sa;
	struct sockaddr_in	*in;
	struct iovec		 iov[5];
	int			 iovcnt = 0;
	uint8_t			 af;

	if (dst->sa_family != ifa->sa_family)
		return (-1);
	af = dst->sa_family;

	iov[iovcnt].iov_base = &af;
	iov[iovcnt].iov_len = sizeof(af);
	iovcnt++;

	iov[iovcnt].iov_base = &rdomain;
	iov[iovcnt].iov_len = sizeof(rdomain);
	iovcnt++;

	switch(af) {
	case AF_INET:
		in = (struct sockaddr_in *)dst;
		iov[iovcnt].iov_base = in;
		iov[iovcnt].iov_len = sizeof(*in);
		iovcnt++;

		bzero(&sa, sizeof(sa));
		in = (struct sockaddr_in *)&sa;
		in->sin_addr.s_addr = prefixlen2mask(mask);
		in->sin_family = af;
		in->sin_len = sizeof(*in);
		iov[iovcnt].iov_base = in;
		iov[iovcnt].iov_len = sizeof(*in);
		iovcnt++;

		in = (struct sockaddr_in *)ifa;
		iov[iovcnt].iov_base = in;
		iov[iovcnt].iov_len = sizeof(*in);
		iovcnt++;
		break;
	case AF_INET6:
		/* XXX: notyet */
		return (-1);
	}

	return (proc_composev(&env->sc_ps, PROC_PARENT, IMSG_VROUTE_ADD,
	    iov, iovcnt));
}

int
vroute_getaddroute(struct iked *env, struct imsg *imsg)
{
	return (vroute_getroute(env, imsg, RTM_ADD));
}

int
vroute_getdelroute(struct iked *env, struct imsg *imsg)
{
	return (vroute_getroute(env, imsg, RTM_DELETE));
}

int
vroute_getroute(struct iked *env, struct imsg *imsg, uint8_t type)
{
	uint8_t			*ptr;
	size_t			 left;
	uint8_t			 af, rdomain;
	int			 i;
	struct sockaddr_in	*in[3];
	struct sockaddr_in6	*in6[3];

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
			if (left < sizeof(*in[i]))
				return (-1);
			in[i] = (struct sockaddr_in *)ptr;
			ptr += sizeof(*in[i]);
			left -= sizeof(*in[i]);
			break;
		case AF_INET6:
			if (left < sizeof(in6[i]))
				return (-1);
			in6[i] = (struct sockaddr_in6 *)ptr;
			ptr += sizeof(*in6[i]);
			left -= sizeof(*in6[i]);
			break;
		default:
			return (-1);
		}
	}

	if (af == AF_INET)
		return (vroute_doroute(env, rdomain, type,
		    (struct sockaddr *)in[0], (struct sockaddr *)in[1],
		    (struct sockaddr *)in[2]));

	return (vroute_doroute(env, rdomain, type,
	    (struct sockaddr *)in6[0], (struct sockaddr *)in6[1],
	    (struct sockaddr *)in6[2]));
}

int
vroute_doroute(struct iked *env, int rdomain, uint8_t type, struct sockaddr *dest,
    struct sockaddr *mask, struct sockaddr *addr)
{
	char			 destbuf[INET_ADDRSTRLEN];
	char			 maskbuf[INET_ADDRSTRLEN];
	char			 gwbuf[INET_ADDRSTRLEN];
	struct iovec		 iov[7];
	struct rt_msghdr	 rtm;
	struct iked_vroute_sc	*ivr = env->sc_vroute;
	struct sockaddr_in	*in;
	int			 iovcnt = 0;
	int			 i;
	long			 pad = 0;
	size_t			 padlen;

	bzero(&rtm, sizeof(rtm));
	rtm.rtm_index = 0;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_tableid = rdomain;
	rtm.rtm_type = type;
	rtm.rtm_seq = ++ivr->ivr_rtseq;
	rtm.rtm_priority = IKED_VROUTE_PRIO;
	rtm.rtm_flags = RTF_UP | RTF_STATIC;
	rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt].iov_len = sizeof(rtm);
	iovcnt++;

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

	log_debug("%s: type: %s rdomain: %d dst: %s mask: %s gw: %s", __func__,
	    type == RTM_ADD ? "RTM_ADD" :
	    (type == RTM_DELETE ? "RTM_DELETE" : "unknown"),
	    rdomain, destbuf, maskbuf, gwbuf);

	for (i = 0; i < iovcnt; i++)
		rtm.rtm_msglen += iov[i].iov_len;

	if (writev(ivr->ivr_rtsock, iov, iovcnt) == -1) {
		if (errno != EEXIST) {
			log_warn("%s: write %d", __func__, rtm.rtm_errno);
			return (-1);
		}
	}
	return (0);
}

int
vroute_addaddr4(struct iked *env, char *ifname, struct in_addr addr, struct in_addr mask)
{
	struct ifaliasreq	 req;
	struct iked_vroute_sc	*ivr = env->sc_vroute;
	struct sockaddr_in	*in;

	bzero(&req, sizeof(req));
	strncpy(req.ifra_name, ifname, sizeof(req.ifra_name));

	in = (struct sockaddr_in *)&req.ifra_addr;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(req.ifra_addr);
	in->sin_addr.s_addr = addr.s_addr;

	in = (struct sockaddr_in *)&req.ifra_mask;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(req.ifra_mask);
	in->sin_addr.s_addr = mask.s_addr;

	if (ioctl(ivr->ivr_iosock, SIOCAIFADDR, &req) == -1) {
		log_warn("%s: SIOCAIFADDR %s", __func__,
		    inet_ntoa(addr));
		return (-1);
	}

	return (0);
}

int
vroute_deladdr4(char *ifname, int fd, struct in_addr addr)
{
	struct ifaliasreq	 req;
	struct sockaddr_in	*in;

	bzero(&req, sizeof(req));
	strncpy(req.ifra_name, ifname, sizeof(req.ifra_name));

	in = (struct sockaddr_in *)&req.ifra_addr;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(req.ifra_addr);
	in->sin_addr.s_addr = addr.s_addr;

	if (ioctl(fd, SIOCDIFADDR, &req) == -1) {
		log_warn("%s: SIOCDIFADDR %s", __func__,
		    inet_ntoa(addr));
		return (-1);
	}

	return (0);
}
