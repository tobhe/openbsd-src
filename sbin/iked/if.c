/*	$OpenBSD: $	*/

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
#include <netinet/in.h>
#include <netinet6/in6_var.h>

#include <event.h>
#include <string.h>
#include <strings.h>

#include <iked.h>

int
if_addaddr4(char *ifname, int fd, struct in_addr addr, struct in_addr mask)
{
	struct ifaliasreq	 req;
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

	if (ioctl(fd, SIOCAIFADDR, &req) == -1) {
		log_warn("%s: SIOCAIFADDR %s", __func__,
		    inet_ntoa(addr));
		return (-1);
	}

	return (0);
}

int
if_deladdr4(char *ifname, int fd, struct in_addr addr)
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
