/*	$OpenBSD$	*/

/*
 * Copyright (c) 2019 Tobias Heider <tobhe@openbsd.org>
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

#ifndef DHCP6_H
#define DHCP6_H

#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#define DHCP6_EXCHANGE_SOLICIT	(1)
#define DHCP6_OPTION_HDR_SIZE	(4u)

struct dhcp6_iana {
	uint32_t	 iana_iaid;
	uint32_t	 iana_t1;
	uint32_t	 iana_t2;
};

struct dhcp6_duid {
	uint8_t		 duid_type;
	uint8_t		*duid_id;
	uint16_t	 duid_len;
};

#define DHCP6_DUID_TYPE_NONE	(0)
#define DHCP6_DUID_TYPE_LLPT	(1)
#define DHCP6_DUID_TYPE_VID	(1)
#define DHCP6_DUID_TYPE_LL	(2)
#define DHCP6_DUID_TYPE_UUID	(3)
#define DHCP6_DUID_TYPE_RAND	(4)

struct dhcp6_duid_llpt {
	uint16_t	 llpt_type;
	uint16_t	 llpt_hwtype;
	uint32_t	 llpt_time;
	/* followd by MAC addr */
} __packed;


TAILQ_HEAD(dhcp6_options, dhcp6_option);
struct dhcp6_option {
	struct dhcp6_options		 option_options;
	TAILQ_ENTRY(dhcp6_option)	 option_entry;
	uint8_t				*option_data;
	size_t				 option_data_len;
	uint16_t			 option_code;
	uint16_t			 option_length;
};

struct dhcp6_opt_iana {
	uint32_t	iana_id;
	uint32_t	iana_t1;
	uint32_t	iana_t2;
};

struct dhcp6_opt_iaaddr {
	struct sockaddr_in6		iaaddr_addr;
	uint8_t				iaaddr_plen;
	uint32_t			iaaddr_pltime;
	uint32_t			iaaddr_vltime;
};

struct dhcp6_msg {
	struct dhcp6_options		msg_options;
	uint8_t				msg_transaction_id[3];
	uint8_t				msg_type;
};

#define DHCP6_MSG_TYPE_NONE		(0)
#define DHCP6_MSG_TYPE_SOLICIT		(1)
#define DHCP6_MSG_TYPE_ADVERTISE	(2)
#define DHCP6_MSG_TYPE_REQUEST		(3)
#define DHCP6_MSG_TYPE_CONFIRM		(4)

#define DHCP6_OPTION_NONE		(0)
#define DHCP6_OPTION_CLIENTID		(1)
#define DHCP6_OPTION_SERVERID		(2)
#define DHCP6_OPTION_IANA		(3)
#define DHCP6_OPTION_IAADDR		(5)
#define DHCP6_OPTION_ELAPSED_TIME	(8)
#define DHCP6_OPTION_RAPID_COMMIT	(14)
#define DHCP6_OPTION_IAPD		(25)
#define DHCP6_OPTION_IAPREFIX		(26)

int			 dhcp6_options_add_option(struct dhcp6_options *, int,
			    void *, size_t);
struct dhcp6_options	*dhcp6_options_add_iana(struct dhcp6_options *, uint32_t,
			    uint32_t, uint32_t);
struct dhcp6_options	*dhcp6_options_add_iapd(struct dhcp6_options *, uint32_t,
			    uint32_t, uint32_t);
struct dhcp6_options	*dhcp6_options_add_ia_addr(struct dhcp6_options *);
struct dhcp6_option *	 dhcp6_options_get_option(struct dhcp6_options *opts,
			    int);
int			 dhcp6_options_iaaddress_verify(struct dhcp6_opt_iaaddr *,
			    uint8_t *);
int			 dhcp6_options_iaprefix_verify(struct dhcp6_opt_iaaddr *,
			    uint8_t *);
ssize_t			 dhcp6_msg_serialize(struct dhcp6_msg *, uint8_t *,
			    ssize_t);
struct dhcp6_msg	*dhcp6_msg_init(uint8_t);
struct dhcp6_msg	*dhcp6_msg_parse(uint8_t*, size_t);
void			 dhcp6_msg_print(struct dhcp6_msg *);
void			 dhcp6_msg_free(struct dhcp6_msg *);
int			 dhcp6_get_duid(struct ether_addr *, uint8_t,
			    struct dhcp6_duid *);

#endif /* DHCP6_H */
