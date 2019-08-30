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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>

struct dhcp6_duid {
	uint8_t		 duid_type;
	uint8_t		*duid_id;
	size_t		 duid_len;
};

#define DHCP6_DUID_TYPE_NONE	(0)
#define DHCP6_DUID_TYPE_LLPT	(1)
#define DHCP6_DUID_TYPE_VID	(1)
#define DHCP6_DUID_TYPE_LL	(2)
#define DHCP6_DUID_TYPE_UUID	(3)

struct dhcp6_duid_llpt {
	uint16_t	 llpt_type;
	uint16_t	 llpt_hwtype;
	uint32_t	 llpt_time;
	/* followd by MAC addr */
} __packed;

struct dhcp6_msg {
	uint8_t					msg_type;
	uint8_t					msg_transaction_id[3];
	SLIST_HEAD(dhcp6_options, dhcp6_option)	msg_options;
};

int		 dhcp6_msg_add_option(struct dhcp6_msg *, int, uint8_t *, size_t);
struct ibuf	*dhcp6_msg_serialize(struct dhcp6_msg *);
struct dhcp6_msg	*dhcp6_msg_init(uint8_t);
struct dhcp6_msg	*dhcp6_msg_parse(uint8_t*, size_t);
void			 dhcp6_msg_print(struct dhcp6_msg *);


int			 dhcp6_get_duid(struct ether_addr *, uint8_t,
			    struct dhcp6_duid *d);
