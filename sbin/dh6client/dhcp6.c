/*	$OpenBSD $	*/

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

#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/queue.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/uio.h>
#include <stdint.h>
#include <imsg.h>

#include "dh6client.h"
#include "dhcp6.h"

/* Thresholds to prevent overflows in parser */
#define DHCP6_OPTIONS_MAX	(64)
#define DHCP6_MESSAGE_LEN_MAX	(512)

static int	buf_write(uint8_t **to, void *from, size_t from_len, size_t *len);
static int	buf_get(void *to, uint8_t **from, size_t to_len, size_t *len);

static struct dhcp6_options *
		dhcp6_options_parse(struct dhcp6_options *, uint8_t*, size_t, int);
static ssize_t	dhcp6_options_serialize(uint8_t **, ssize_t, struct dhcp6_options *, int);
static size_t	dhcp6_options_get_length(struct dhcp6_options *, int);
static void	dhcp6_options_free(struct dhcp6_options *, int);


int
buf_write(uint8_t **to, void *from, size_t from_len, size_t *len)
{
	if (from_len > *len)
		return (-1);
	if (memcpy(*to, from, from_len) == NULL)
		return (-1);
	*to += from_len;
	*len -= from_len;
	return (0);
}

int
buf_get(void *to, uint8_t **from, size_t to_len, size_t *len)
{
	if (*len < to_len) {
		log_debug("%s: invalid length, %zu > %zu", __func__, *len,
		    to_len);
		return (-1);
	}
	if (memcpy(to, *from, to_len) == NULL)
		return (-1);
	*from += to_len;
	*len -= to_len;
	return (0);
}

/*
 * Print contents of a DHCPv6 message
 */
void
dhcp6_msg_print(struct dhcp6_msg *msg)
{
	struct dhcp6_option	*opt, *opt2, *opt3;
	size_t			 i;

	printf("Print DHCPv6 Message:\n");
	printf("\tMessage Type:\t%"PRIu8"\n", msg->msg_type);
	printf("\tMessage Transaction ID:\t");
	for (i = 0; i < sizeof(msg->msg_transaction_id); i++) {
		printf("%02"PRIx8, msg->msg_transaction_id[i]);
	}
	printf("\n");
	printf("\tOptions:\n");
	TAILQ_FOREACH(opt, &msg->msg_options, option_entry) {
		printf("\t\tOption Code:\t%"PRIu16"\n", opt->option_code);
		printf("\t\tOption Length:\t%"PRIu16"\n", opt->option_length);
		printf("\t\tOption Data:\t");
		for (i = 0; i < opt->option_data_len; i++) {
			printf("%02"PRIx8, opt->option_data[i]);
		}
		printf("\n\n");
		if (!TAILQ_EMPTY(&opt->option_options)) {
			printf("\t\tOptions:\n");
			TAILQ_FOREACH(opt2, &opt->option_options, option_entry) {
				printf("\t\t\tOption Code:\t%"PRIu16"\n", opt2->option_code);
				printf("\t\t\tOption Length:\t%"PRIu16"\n", opt2->option_length);
				printf("\t\t\tOption Data:\t");
				for (i = 0; i < opt2->option_data_len; i++) {
					printf("%02"PRIx8, opt2->option_data[i]);
				}
				printf("\n\n");
				if (!TAILQ_EMPTY(&opt2->option_options)) {
					printf("\t\t\tOptions:\n");
					TAILQ_FOREACH(opt3, &opt2->option_options, option_entry) {
						printf("\t\t\t\tOption Code:\t%"PRIu16"\n", opt3->option_code);
						printf("\t\t\t\tOption Length:\t%"PRIu16"\n", opt3->option_length);
						printf("\t\t\t\tOption Data:\t");
						for (i = 0; i < opt3->option_data_len; i++) {
							printf("%02"PRIx8, opt3->option_data[i]);
						}
						printf("\n\n");
					}
				}
			}
		}
	}
}

/*
 * Initialize message header. Setup random transaction ID and list of options.
 */
struct dhcp6_msg *
dhcp6_msg_init(uint8_t type)
{
	struct dhcp6_msg	*msg;

	if ((msg = calloc(1, sizeof(*msg))) == NULL)
		return NULL;

	msg->msg_type = type;
	arc4random_buf(msg->msg_transaction_id, sizeof(msg->msg_transaction_id));
	TAILQ_INIT(&msg->msg_options);

	return msg;
}

void
dhcp6_msg_free(struct dhcp6_msg *msg)
{
	dhcp6_options_free(&msg->msg_options, 0);
	free(msg);
}

void
dhcp6_options_free(struct dhcp6_options *opts, int depth)
{
	struct dhcp6_option	*opt, *tmp;

	TAILQ_FOREACH_SAFE(opt, opts, option_entry, tmp) {
		/* Limit recursion depth to 2. */
		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 3)
			dhcp6_options_free(&opt->option_options, depth);
		if (opt->option_data != NULL) {
			free(opt->option_data);
			opt->option_data = NULL;
		}
		TAILQ_REMOVE(opts, opt, option_entry);
		free(opt);
		opt = NULL;
	}
}

struct dhcp6_option *
dhcp6_options_get_option(struct dhcp6_options *opts, int code)
{
	struct dhcp6_option	*opt;

	TAILQ_FOREACH(opt, opts, option_entry) {
		if (opt->option_code == code)
			return opt;
	}
	return (NULL);
}

int
dhcp6_options_iaaddress_verify(struct dhcp6_opt_iaaddr *iaaddr,
    uint8_t *data)
{
	bzero(iaaddr, sizeof(*iaaddr));

	/* Address */
	if (memcpy(&iaaddr->iaaddr_addr.sin6_addr, data,
	    sizeof(iaaddr->iaaddr_addr.sin6_addr)) == NULL)
		return (-1);
	data += sizeof(iaaddr->iaaddr_addr.sin6_addr);
	iaaddr->iaaddr_addr.sin6_len = sizeof(struct sockaddr_in6);
	iaaddr->iaaddr_addr.sin6_family = PF_INET6;

	/* T1 */
	if (memcpy(&iaaddr->iaaddr_vltime, data, sizeof(iaaddr->iaaddr_vltime)) == NULL)
		return (-1);
	iaaddr->iaaddr_vltime = ntohl(iaaddr->iaaddr_vltime);
	data += sizeof(iaaddr->iaaddr_vltime);

	/* T2 */
	if (memcpy(&iaaddr->iaaddr_pltime, data, sizeof(iaaddr->iaaddr_pltime)) == NULL)
		return (-1);
	iaaddr->iaaddr_pltime = ntohl(iaaddr->iaaddr_pltime);
	data += sizeof(iaaddr->iaaddr_pltime);

	if (iaaddr->iaaddr_pltime > iaaddr->iaaddr_vltime)
		return (-1);

	return (0);
}

int
dhcp6_options_iaprefix_verify(struct dhcp6_opt_iaaddr *iaaddr,
    uint8_t *data)
{
	bzero(iaaddr, sizeof(*iaaddr));

	/* Prefix */
	if (memcpy(&iaaddr->iaaddr_plen, data,
	    sizeof(iaaddr->iaaddr_plen)) == NULL)
		return (-1);
	data += sizeof(iaaddr->iaaddr_plen);

	/* Address */
	if (memcpy(&iaaddr->iaaddr_addr.sin6_addr, data,
	    sizeof(iaaddr->iaaddr_addr.sin6_addr)) == NULL)
		return (-1);
	data += sizeof(iaaddr->iaaddr_addr.sin6_addr);
	iaaddr->iaaddr_addr.sin6_len = sizeof(struct sockaddr_in6);
	iaaddr->iaaddr_addr.sin6_family = PF_INET6;

	/* T1 */
	if (memcpy(&iaaddr->iaaddr_vltime, data, sizeof(iaaddr->iaaddr_vltime)) == NULL)
		return (-1);
	ntohl(iaaddr->iaaddr_vltime);
	data += sizeof(iaaddr->iaaddr_vltime);

	/* T2 */
	if (memcpy(&iaaddr->iaaddr_pltime, data, sizeof(iaaddr->iaaddr_pltime)) == NULL)
		return (-1);
	ntohl(iaaddr->iaaddr_pltime);
	data += sizeof(iaaddr->iaaddr_pltime);

	if (iaaddr->iaaddr_pltime > iaaddr->iaaddr_vltime)
		return (-1);

	return (0);
}


/*
 * Add new option to list of options.
 * XXX: Change add option to start sublist and return pointer to objs
 */
int
dhcp6_options_add_option(struct dhcp6_options *opts, int code, void *data,
    size_t length)
{
	struct dhcp6_option 	*opt;
	uint8_t			*bytes = data;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (-1);

	if (data != NULL) {
		opt->option_data = calloc(1, length);
		memcpy(opt->option_data, bytes, length);
	}

	opt->option_code = code;
	opt->option_data_len = length;

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);

	return (0);
}

struct dhcp6_options *
dhcp6_options_add_iana(struct dhcp6_options *opts, uint32_t id, uint32_t t1,
    uint32_t t2)
{
	struct dhcp6_option 	*opt;
	uint8_t			*p;
	size_t			 len;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (NULL);

	opt->option_code = DHCP6_OPTION_IANA;
	opt->option_data_len = len = 12;
	opt->option_data = calloc(3, sizeof(uint32_t));
	p = opt->option_data;
	if (buf_write(&p, &id, sizeof(id), &len) == -1)
		return (NULL);
	if (buf_write(&p, &t1, sizeof(t1), &len) == -1)
		return (NULL);
	if (buf_write(&p, &t1, sizeof(t1), &len) == -1)
		return (NULL);

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);

	return (&opt->option_options);
}

struct dhcp6_options *
dhcp6_options_add_iapd(struct dhcp6_options *opts, uint32_t id, uint32_t t1,
    uint32_t t2)
{
	struct dhcp6_option 	*opt;
	uint8_t			*p;
	size_t			 len;
	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (NULL);

	opt->option_code = DHCP6_OPTION_IAPD;
	opt->option_data_len = len = 12;
	opt->option_data = calloc(3, sizeof(uint32_t));
	p = opt->option_data;
	if (buf_write(&p, &id, sizeof(id), &len) == -1)
		return (NULL);
	if (buf_write(&p, &t1, sizeof(t1), &len) == -1)
		return (NULL);
	if (buf_write(&p, &t1, sizeof(t1), &len) == -1)
		return (NULL);

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);

	return (&opt->option_options);
}

/*
 * Add new option of type IA_ADDRESS to list of options.
 */
struct dhcp6_options *
dhcp6_options_add_ia_addr(struct dhcp6_options *opts)
{
	struct dhcp6_option 	*opt;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (NULL);

	opt->option_code = DHCP6_OPTION_IAADDR;
	opt->option_data_len = 24;
	opt->option_data = calloc(1, 24);

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);

	return (&opt->option_options);
}

/*
 * Calculate and store length of a chain of options recursively.
 */
size_t
dhcp6_options_get_length(struct dhcp6_options *opts, int depth)
{
	struct dhcp6_option	*opt;
	size_t			 len = 0, olen;

	TAILQ_FOREACH(opt, opts, option_entry) {
		olen = 0;
		/* Limit depth to 2 to prevent stack exhaustion */
		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 3)
			olen += dhcp6_options_get_length(&opt->option_options, depth);
		opt->option_length = opt->option_data_len + olen;
		len += opt->option_length + 4;
	}
	return len;
}

/*
 * Write DHCP6 msg to buffer of size length.
 */
ssize_t
dhcp6_msg_serialize(struct dhcp6_msg *msg, uint8_t *buf, ssize_t length)
{
	ssize_t			 rlen;
	ssize_t			 left = length;

	/* Calculate list lengths */
	if ((rlen = dhcp6_options_get_length(&msg->msg_options, 0)) > length) {
		printf("size_mismatch: %ld, %zu\n", rlen, length);
		return (-1);
	}

	/* Message Header */
	if (buf_write(&buf, &msg->msg_type, sizeof(msg->msg_type),
	    &left) == -1)
		return (-1);

	if (buf_write(&buf, &msg->msg_transaction_id,
	    sizeof(msg->msg_transaction_id), &left) == -1)
		return (-1);

	/* Options */
	if ((left = dhcp6_options_serialize(&buf, left, &msg->msg_options, 0)) == -1)
		return (-1);

	return (length - left);
}

ssize_t
dhcp6_options_serialize(uint8_t **buf, ssize_t left, struct dhcp6_options *opts, int depth)
{
	struct dhcp6_option	*opt;
	uint16_t		 h;

	/* Options */
	TAILQ_FOREACH(opt, opts, option_entry) {
		h = htons(opt->option_code);
		if (buf_write(buf, &h, sizeof(h), &left) == -1)
			return (-1);
		h = htons(opt->option_length);
		if (buf_write(buf, &h, sizeof(h), &left) == -1)
			return (-1);
		if (buf_write(buf, opt->option_data, opt->option_data_len,
		    &left) == -1)
			return (-1);

		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 3){
			left = dhcp6_options_serialize(buf, left,
			    &opt->option_options, depth);
		}
	}
	return (left);
}

struct dhcp6_msg *
dhcp6_msg_parse(uint8_t* data, size_t length)
{
	struct dhcp6_msg	*msg;

	msg = calloc(1, sizeof(*msg));
	TAILQ_INIT(&msg->msg_options);

	/* Header */
	if (buf_get(&msg->msg_type, &data,
	    sizeof(msg->msg_type), &length) == -1)
		goto clean;
	if (buf_get(&msg->msg_transaction_id, &data,
	    sizeof(msg->msg_transaction_id), &length) == -1)
		goto clean;

	/* Options */
	if (dhcp6_options_parse(&msg->msg_options, data, length, 0) == NULL) {
		log_warn("%s: Failed to parse options.\n", __func__);
		goto clean;
	}
	return (msg);
 clean:
	dhcp6_msg_free(msg);
	return (NULL);
}

struct dhcp6_options *
dhcp6_options_parse(struct dhcp6_options *opts, uint8_t* data, size_t length,
    int depth)
{
	struct dhcp6_option	*opt;
	size_t			 olen;
	size_t			 count = 0;

	while (length > 0 && count < DHCP6_OPTIONS_MAX) {
		if ((opt = calloc(1, sizeof(*opt))) == NULL) {
			log_warn("Failed calloc.\n");
			return (NULL);
		}
		TAILQ_INIT(&opt->option_options);

		if (buf_get(&opt->option_code, &data, sizeof(opt->option_code),
		    &length) == -1)
			goto clean;
		opt->option_code = ntohs(opt->option_code);

		if (buf_get(&opt->option_length, &data, sizeof(opt->option_length),
		    &length) == -1)
			goto clean;

		opt->option_length = ntohs(opt->option_length);
		if (opt->option_length > 512) {
			log_debug("%s: invalid size value.", __func__);
			goto clean;
		}

		switch(opt->option_code) {
		case DHCP6_OPTION_IANA:
		case DHCP6_OPTION_IAPD:
			olen = 3 * sizeof(uint32_t);
			opt->option_data = calloc(1, olen);
			opt->option_data_len = olen;
			if (buf_get(opt->option_data, &data, olen, &length) == -1)
				return (NULL);
			if (opt->option_length - olen > 0) {
				/* Recursion depth limited to 3.*/
				if (++depth > 2)
					return NULL;
				dhcp6_options_parse(&opt->option_options,
				    data, opt->option_length - olen, depth);
				length -= opt->option_length - olen;
				data += opt->option_length - olen;
			}
			break;
		case DHCP6_OPTION_IAADDR:
			olen = 2 * sizeof(uint64_t) + 2 * sizeof(uint32_t);
			opt->option_data = calloc(1, olen);
			opt->option_data_len = olen;
			if (buf_get(opt->option_data, &data, olen, &length) == -1)
				return (NULL);
			if (opt->option_length - olen > 0) {
				/* Recursion depth limited to 3.*/
				if (++depth > 2)
					goto clean;
				dhcp6_options_parse(&opt->option_options,
				    data, opt->option_length - olen, depth);
				length -= opt->option_length - olen;
				data += opt->option_length - olen;
			}
			break;
		default:
			if (opt->option_length > 0 ) {
				opt->option_data = calloc(1, opt->option_length);
				opt->option_data_len = opt->option_length;
				if (buf_get(opt->option_data, &data,
				    opt->option_length, &length) == -1)
					return (NULL);
			}
			break;
		}
		TAILQ_INSERT_TAIL(opts, opt, option_entry);
		++count;
	}
	return opts;
 clean:
	dhcp6_options_free(opts, depth);
	return (NULL);
}

int
dhcp6_get_duid(struct ether_addr *mac,
    uint8_t type, struct dhcp6_duid *d)
{
	struct dhcp6_duid_llpt		*llpt;
	size_t				 len;
	uint64_t			 t;
	int				 ret = -1;

	if (d == NULL)
		return ret;

	d->duid_type = type;

	switch (type) {
	case DHCP6_DUID_TYPE_LLPT:
		len = ETHER_ADDR_LEN + sizeof(struct dhcp6_duid_llpt);

		d->duid_id = calloc(1, len);
		llpt = (struct dhcp6_duid_llpt *)d->duid_id;

		llpt->llpt_type = htons(type);
		llpt->llpt_hwtype = htons(type);
		t = (uint64_t)(time(NULL) - 946684800);
		llpt->llpt_time = htonl((uint32_t)(t & 0xffffffff));

		memcpy(llpt + 1, &mac->ether_addr_octet, ETHER_ADDR_LEN);

		d->duid_len = len;
		ret = 0;
		break;
	case DHCP6_DUID_TYPE_RAND:
		/* Fake type 1 for compatibiltity */
		len = ETHER_ADDR_LEN + sizeof(uint64_t);
		d->duid_id = calloc(1, len);
		llpt = (struct dhcp6_duid_llpt *)d->duid_id;

		llpt->llpt_type = htons(1);
		llpt->llpt_hwtype = htons(1);
		arc4random_buf(&llpt->llpt_time,
		    ETHER_ADDR_LEN + sizeof(uint32_t));

		d->duid_len = len;
		ret = 0;
		break;
	default:
		log_debug("%s: Unknown type %"PRIu8".", __func__, type);
		break;
	}
	return ret;
}

