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

static int	buf_write(void **to, void *from, size_t from_len, size_t *len);
static int	buf_get(void *to, void **from, size_t to_len, size_t *len);

static struct dhcp6_options *
		dhcp6_options_parse(struct dhcp6_options *, uint8_t*, size_t, int);
static ssize_t	dhcp6_options_serialize(uint8_t *, struct dhcp6_options *, int);
static size_t	dhcp6_options_get_length(struct dhcp6_options *, int);
static void	dhcp6_options_free(struct dhcp6_options *, int);


int
buf_write(void **to, void *from, size_t from_len, size_t *len)
{
	if (memcpy(*to, from, from_len) == NULL)
		return (-1);
	*to = (uint8_t*)*to + from_len;
	*len += from_len;
	return (0);
}

int
buf_get(void *to, void **from, size_t to_len, size_t *len)
{
	if (memcpy(to, *from, to_len) == NULL)
		return (-1);
	*from = (uint8_t*)*from + to_len;
	*len -= to_len;
	return (0);
}

/*
 * Print contents of a DHCPv6 message
 */
void
dhcp6_msg_print(struct dhcp6_msg *msg)
{
	struct dhcp6_option	*opt, *opt2;
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
		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 2)
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

/*
 * Add new option to list of options.
 */
int
dhcp6_options_add_option(struct dhcp6_options *opts, int code, void *data,
    size_t length)
{
	struct dhcp6_option 	*opt;
	uint8_t			*bytes = data;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (-1);

	opt->option_data = calloc(1, length);
	memcpy(opt->option_data, bytes, length);

	opt->option_code = code;
	opt->option_data_len = length;

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);

	return (0);
}

/*
 * Add new option of type IA_NA to list of options.
 */
struct dhcp6_options *
dhcp6_options_add_iana(struct dhcp6_options *opts, uint32_t id, uint32_t t1,
    uint32_t t2)
{
	struct dhcp6_option 	*opt;
	uint32_t		*p;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (NULL);

	opt->option_code = DHCP6_OPTION_IANA;
	opt->option_data_len = 12;
	opt->option_data = calloc(3, sizeof(uint32_t));
	p = (uint32_t*)opt->option_data;

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);
	p[0] = id;
	p[1] = t1;
	p[2] = t2;

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
		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 2)
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
	ssize_t			 total_len = 0, opt_len, rlen;

	/* Calculate list lengths */
	if ((rlen = dhcp6_options_get_length(&msg->msg_options, 0)) > length) {
		printf("size_mismatch: %ld, %zu\n", rlen, length);
		return (-1);
	}

	/* Message Header */
	if (buf_write((void**)&buf, &msg->msg_type, sizeof(msg->msg_type),
	    &total_len) == -1)
		return (-1);

	if (buf_write((void**)&buf, &msg->msg_transaction_id,
	    sizeof(msg->msg_transaction_id), &total_len) == -1)
		return (-1);

	/* Options */
	if ((opt_len = dhcp6_options_serialize(buf, &msg->msg_options, 0)) == -1)
		return (-1);

	return (opt_len + total_len);
}

ssize_t
dhcp6_options_serialize(uint8_t *buf, struct dhcp6_options *opts, int depth)
{
	struct dhcp6_option	*opt;
	uint16_t		 h;
	ssize_t			 w_len = 0, o_len, t_len;

	/* Options */
	TAILQ_FOREACH(opt, opts, option_entry) {
		o_len = 0;
		h = htons(opt->option_code);
		if (buf_write((void**)&buf, &h, sizeof(h), &o_len) == -1)
			return (-1);
		h = htons(opt->option_length);
		if (buf_write((void**)&buf, &h, sizeof(h), &o_len) == -1)
			return (-1);
		if (buf_write((void**)&buf, opt->option_data, opt->option_data_len,
		    &o_len) == -1)
			return (-1);

		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 2){
			t_len = dhcp6_options_serialize(buf,
			    &opt->option_options, depth);
			buf += t_len;
			o_len += t_len;
		}
		w_len += o_len;
	}
	return (w_len);
}

struct dhcp6_msg *
dhcp6_msg_parse(uint8_t* data, size_t length)
{
	struct dhcp6_msg	*msg;

	msg = calloc(1, sizeof(*msg));
	TAILQ_INIT(&msg->msg_options);

	/* Header */
	buf_get(&msg->msg_type, (void **)&data, sizeof(msg->msg_type), &length);
	buf_get(&msg->msg_transaction_id, (void **)&data, sizeof(msg->msg_transaction_id), &length);

	/* Options */
	if (dhcp6_options_parse(&msg->msg_options, data, length, 0) == NULL) {
		printf("Failed to parse options.\n");
		free(msg);
		return (NULL);
	}
	return (msg);
}

struct dhcp6_options *
dhcp6_options_parse(struct dhcp6_options *opts, uint8_t* data, size_t length,
    int depth)
{
	struct dhcp6_option	*opt;
	size_t			 olen;

	while (length) {
		if ((opt = calloc(1, sizeof(*opt))) == NULL) {
			printf("Failed calloc.\n");
			return (NULL);
		}
		TAILQ_INIT(&opt->option_options);

		buf_get(&opt->option_code, (void **)&data, sizeof(opt->option_code), &length);
		opt->option_code = ntohs(opt->option_code);

		buf_get(&opt->option_length, (void **)&data, sizeof(opt->option_length), &length);
		opt->option_length = ntohs(opt->option_length);

		switch(opt->option_code) {
		case DHCP6_OPTION_IANA:
			olen = 3 * sizeof(uint32_t);
			opt->option_data = calloc(1, olen);
			opt->option_data_len = olen;
			buf_get(opt->option_data, (void **)&data, olen, &length);
			if (opt->option_length - olen > 0) {
				/* Recursion depth limited to 2.*/
				if (++depth > 1)
					return NULL;
				dhcp6_options_parse(&opt->option_options,
				    data, opt->option_length - olen, depth);
				length -= opt->option_length - olen;
				data += opt->option_length - olen;
			}
			break;
		default:
			if (opt->option_length) {
				opt->option_data = calloc(1, opt->option_length);
				opt->option_data_len = opt->option_length;
				buf_get(opt->option_data, (void **)&data,
				    opt->option_length, &length);
			}
			break;
		}
		TAILQ_INSERT_TAIL(opts, opt, option_entry);
	}
	return opts;
}

int
dhcp6_get_duid(struct ether_addr *mac,
    uint8_t type, struct dhcp6_duid *duid)
{
	struct dhcp6_duid_llpt		*llpt;
	size_t				 len;
	uint64_t			 t;
	int				 ret = -1;

	duid->duid_type = type;

	switch (type) {
	case  DHCP6_DUID_TYPE_LLPT:
		len = ETHER_ADDR_LEN + sizeof(struct dhcp6_duid_llpt);

		duid->duid_id = calloc(1, len);
		llpt = (struct dhcp6_duid_llpt *)duid->duid_id;

		llpt->llpt_type = htons(1);
		llpt->llpt_hwtype = htons(type);
		t = (uint64_t)(time(NULL) - 946684800);
		llpt->llpt_time = htonl((uint32_t)(t & 0xffffffff));

		memcpy(llpt + 1, &mac->ether_addr_octet, ETHER_ADDR_LEN);

		duid->duid_len = len;
		ret = 0;
		break;
	default:
		log_debug("%s: Unknown type %"PRIu8".", __func__, type);
		break;
	}
	return ret;
}

#define DHCP6_EXCHANGE_SOLICIT	(1)
#define DHCP6_OPTION_HDR_SIZE	(4u)

