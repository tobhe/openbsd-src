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


#ifndef DH6CLIENT_H
#define DH6CLIENT_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/cdefs.h>

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <stdarg.h>
#include <stdint.h>
#include <imsg.h>
#include "event.h"
#include "dhcp6.h"

#define	DH6CLIENT_SOCKET	"/dev/dh6client.sock"
#define	DH6CLIENT_USER		"_slaacd"
#define	DH6CLIENT_RTA_LABEL	"dh6client"

#define	IMSG_DATA_SIZE(imsg)	((imsg).hdr.len - IMSG_HEADER_SIZE)

enum if_state {
	IF_DOWN,
	IF_DELAY,
	IF_PROBE,
	IF_IDLE,
};

struct dh6client_server {
	struct sockaddr_in6	addr;
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
	int				 sol_max_rt;
	LIST_HEAD(, dh6client_server)	 dhcp_servers;
};
LIST_HEAD(, dh6client_iface) dh6client_interfaces;

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
	IMSG_DHCP6,
	IMSG_SOCKET_IPC,
	IMSG_DHCP6SOCK,
	IMSG_UPDATE_IF,
	IMSG_STARTUP,
	IMSG_STARTUP_DONE,
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
void		 imsg_event_add(struct imsgev *);
int		 imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
		    int, void *, uint16_t);

/* util.c */
void		 print_debug(const char *, ...);
void		 print_hex(uint8_t *,  off_t, size_t);

/* engine.c */
void		 engine(int, int);
int		 engine_imsg_compose_frontend(int, pid_t, void *, uint16_t);
int		 dh6client_send_solicit(struct dh6client_iface *);

/* frontend.c */
void		 frontend(int, int);
void		 frontend_dispatch_main(int, short, void *);
void		 frontend_dispatch_engine(int, short, void *);
int		 frontend_imsg_compose_main(int, pid_t, void *, uint16_t);
int		 frontend_imsg_compose_engine(int, uint32_t, pid_t, void *,
		     uint16_t);

/* log.c */
void	log_init(int, int);
void	log_procinit(const char *);
void	log_setverbose(int);
int	log_getverbose(void);
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warnx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
__dead void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
__dead void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));

/* test.c */
int		 test_parser(void);

#endif /* DH6CLIENT_H */
