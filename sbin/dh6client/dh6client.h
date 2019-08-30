/*	$OpenBSD$	*/

/*
 * Copyright (c) 2019 Tobias Heider <tobhe@openbsd.org>
 * Copyright (c) 2017 Florian Obser <florian@openbsd.org>
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

#include "netinet/in.h"
#include <net/if.h>
#include <netinet/if_ether.h>
#include "event.h"

#define	DH6CLIENT_SOCKET		"/dev/dh6client.sock"
#define DH6CLIENT_USER		"_slaacd"
#define DH6CLIENT_RTA_LABEL	"dh6client"

#define DH6CLIENT_SOIIKEY_LEN	16

/* MAXDNAME from arpa/namesr.h */
#define DH6CLIENT_MAX_DNSSL	1025

#define	IMSG_DATA_SIZE(imsg)	((imsg).hdr.len - IMSG_HEADER_SIZE)

static const char * const log_procnames[] = {
	"main",
	"engine",
	"frontend"
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_SEND_SOLICITATION,
	IMSG_SOCKET_IPC,
	IMSG_ICMP6SOCK,
	IMSG_DHCP6SOCK,
	IMSG_ROUTESOCK,
	IMSG_CONTROLFD,
	IMSG_STARTUP,
	IMSG_STARTUP_DONE,
	IMSG_UPDATE_IF,
	IMSG_REMOVE_IF,
	IMSG_DHCP6,
	IMSG_PROPOSAL,
	IMSG_PROPOSAL_ACK,
	IMSG_CONFIGURE_ADDRESS,
	IMSG_DEL_ADDRESS,
	IMSG_DEL_ROUTE,
	IMSG_FAKE_ACK,
	IMSG_CONFIGURE_DFR,
	IMSG_WITHDRAW_DFR,
	IMSG_DUP_ADDRESS,
};

enum {
	PROC_MAIN,
	PROC_ENGINE,
	PROC_FRONTEND
} dh6client_process;

struct imsg_ifinfo {
	uint32_t		if_index;
	int			running;
	struct ether_addr	hw_address;
};

struct imsg_dhcp6 {
	uint32_t		if_index;
	struct sockaddr_in6	from;
	ssize_t			len;
	uint8_t			packet[1500];
};

/* dh6client.c */
void		imsg_event_add(struct imsgev *);
int		imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
		    int, void *, uint16_t);
int		test_parser(void);

#ifndef	SMALL
const char	*sin6_to_str(struct sockaddr_in6 *);
#else
#define	sin6_to_str(x...)	""
#endif	/* SMALL */
