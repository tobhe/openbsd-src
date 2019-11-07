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

#define	DH6CLIENT_SOCKET	"/dev/dh6client.sock"
#define	DH6CLIENT_USER		"_slaacd"
#define	DH6CLIENT_RTA_LABEL	"slaacd"
#define	DH6CLIENT_DUID_FILE	"/etc/duid"

#define	IMSG_DATA_SIZE(imsg)	((imsg).hdr.len - IMSG_HEADER_SIZE)

#define	DH6CLIENT_IFACE_OPTION_RAPID	(0x01)

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
	IMSG_DHCP6,
	IMSG_DHCP6SOCK,
	IMSG_DUID,
	IMSG_NONE,
	IMSG_SOCKET_IPC,
	IMSG_ROUTESOCK,
	IMSG_STARTUP,
	IMSG_STARTUP_DONE,
	IMSG_UPDATE_IF,
	IMSG_REMOVE_IF,
	IMSG_CONFIGURE_ADDRESS,
};

enum {
	PROC_MAIN,
	PROC_ENGINE,
	PROC_FRONTEND
} dh6client_process;

struct imsg_ifinfo {
	struct ether_addr	hw_address;
	int			running;
	uint32_t		if_index;
};

struct imsg_dhcp6 {
	uint32_t		if_index;
	struct sockaddr_in6	from;
	ssize_t			len;
	uint8_t			packet[1500];
};

struct dhcp6_duid	 duid;

/* dh6client.c */
void		imsg_event_add(struct imsgev *);
int		imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
		    int, void *, uint16_t);
