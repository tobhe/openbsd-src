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

#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "dhcp6.h"

/* Thresholds against overflows */
#define DHCP6_OPTIONS_DEPTH_MAX		(3)
#define DHCP6_MSG_LEN_MAX		(512)
#define DHCP6_OPTIONS_MAX		(64)

const char* dhcp6_msg_type_name[] = {
	"NONE",
	"SOLICIT",
	"ADVERTISE",
	"REQUEST",
	"CONFIRM",
	"RENEW",
	"REBIND",
	"REPLY",
	"RELEASE",
	"DECLINE",
};

struct dhcp6_constmap {
	unsigned int	 cm_type;
	const char	* const cm_name;
};

const struct dhcp6_constmap options_map[] = {
	{ DHCP6_OPTION_NONE,			"NONE" },
	{ DHCP6_OPTION_CLIENTID,		"CLIENTID" },
	{ DHCP6_OPTION_SERVERID,		"SERVERID"},
	{ DHCP6_OPTION_IANA,			"IA_NA" },
	{ DHCP6_OPTION_IAADDR,			"IAADDR" },
	{ DHCP6_OPTION_ELAPSED_TIME,		"ELAPSED_TIME" },
	{ DHCP6_OPTION_STATUSCODE,		"STATUS_CODE" },
	{ DHCP6_OPTION_RAPID_COMMIT,		"RAPID_COMMIT" },
	{ DHCP6_OPTION_IAPD,			"IA_PD" },
	{ DHCP6_OPTION_IAPREFIX,		"IA_PREFIX" },
	{ 0 },
};

static int	buf_write(uint8_t **, void *, size_t, size_t *);
static int	buf_get(void *, uint8_t **, size_t, size_t *);

static struct dhcp6_options *
		 dhcp6_options_parse(struct dhcp6_options *, uint8_t*, size_t,
		    int);
static ssize_t	 dhcp6_options_serialize(uint8_t **, ssize_t,
		    struct dhcp6_options *, int);
static size_t	 dhcp6_options_get_length(struct dhcp6_options *, int);
static void	 dhcp6_options_free(struct dhcp6_options *, int);
static void	 dhcp6_options_print(struct dhcp6_options *, int);
const char	*print_map(unsigned int type, const struct dhcp6_constmap *);

const char *
print_map(unsigned int type, const struct dhcp6_constmap *map)
{
	unsigned int		 i;

	for (i = 0; map[i].cm_name != NULL; i++) {
		if (map[i].cm_type == type)
			return map[i].cm_name;
	}
	return "<unknown>";
}

int
buf_write(uint8_t **to, void *from, size_t from_len, size_t *len)
{
	if (from_len > *len) {
		log_debug("%s: invalid length, %zu > %zu", __func__, from_len,
		    *len);
		return (-1);
	}
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
		log_debug("%s: invalid length, %zu < %zu", __func__, *len,
		    to_len);
		return (-1);
	}
	if (memcpy(to, *from, to_len) == NULL)
		return (-1);
	*from += to_len;
	*len -= to_len;
	return (0);
}

void
dhcp6_msg_print(struct dhcp6_msg *msg)
{
	printf("Print DHCPv6 Message:\n");
	printf("\tMessage Type:\t%d\n", msg->msg_type);
	dhcp6_options_print(&msg->msg_options, 0);
}

void
dhcp6_options_print(struct dhcp6_options *opts, int depth)
{
	struct dhcp6_option	*opt;
	size_t			 i;
	char			 tabs[4];

	memset(tabs, 0, sizeof(tabs));
	memset(tabs, '\t', depth);
	printf("\t%sOptions:\n", tabs);
	TAILQ_FOREACH(opt, opts, option_entry) {
		printf("\t\t%sOption Code:\t(%hu): %s\n", tabs,
		    opt->option_code, print_map(opt->option_code, options_map));
		printf("\t\t%sOption Length:\t%hu\n", tabs, opt->option_length);
		switch (opt->option_code) {
		case DHCP6_OPTION_IAADDR: {
			struct dhcp6_opt_iaaddr	 iaaddr;
			char			 buffer[INET6_ADDRSTRLEN];
			const char		*ptr;
			if ((ptr = inet_ntop(AF_INET6, opt->option_data,
			    buffer, sizeof(buffer))) == NULL)
				break;
			printf("\t\t%sAddress:\t%s\n", tabs, ptr);
			dhcp6_options_iaaddress_verify(&iaaddr,
			    opt->option_data, 0);
			printf("\t\t%sPreferred Lifetime:\t%ds\n", tabs,
			    iaaddr.iaaddr_pltime);
			printf("\t\t%sValid Lifetime:\t%ds\n", tabs,
			    iaaddr.iaaddr_vltime);
			break;
		}
		case DHCP6_OPTION_STATUSCODE: {
			struct dhcp6_opt_statuscode	 status;
			dhcp6_options_statuscode_verify(&status,
			    opt->option_data,
			    opt->option_data_len);
			printf("\t\t%sStatus: [%u]: %s\n", tabs,
			    status.status_code, status.status_msg);
			break;
		}
		default:
			if (opt->option_length == 0)
				break;
			printf("\t\t%sBytes:\t", tabs);
			for (i = 0; i < opt->option_data_len && opt->option_data;
			    i++) {
				printf("%02x", opt->option_data[i]);
			}
			printf("\n");
			break;
		}
		printf("\n");
		if (!TAILQ_EMPTY(&opt->option_options) &&
		    ++depth < DHCP6_OPTIONS_DEPTH_MAX)
			dhcp6_options_print(&opt->option_options, depth);
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
	arc4random_buf(msg->msg_transaction_id,
	    sizeof(msg->msg_transaction_id));
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
		if (!TAILQ_EMPTY(&opt->option_options) &&
		    ++depth < DHCP6_OPTIONS_DEPTH_MAX)
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
dhcp6_options_statuscode_verify(struct dhcp6_opt_statuscode *status,
    uint8_t *p, size_t left)
{
	memset(status, 0, sizeof(*status));

	/* Code */
	if (buf_get(&status->status_code, &p, sizeof(status->status_code),
	    &left) == -1)
		return (-1);
	status->status_code = htons(status->status_code);

	/* Message */
	status->status_msg = calloc(sizeof(char), left + 1);
	if (buf_get(status->status_msg, &p, left, &left) == -1) {
		free(status->status_msg);
		return (-1);
	}
	return (0);
}

int
dhcp6_options_iaaddress_verify(struct dhcp6_opt_iaaddr *iaaddr,
    uint8_t *data, int prefix)
{
	bzero(iaaddr, sizeof(*iaaddr));

	if (prefix) {
		/* Prefix */
		if (memcpy(&iaaddr->iaaddr_plen, data,
		    sizeof(iaaddr->iaaddr_plen)) == NULL)
			return (-1);
		data += sizeof(iaaddr->iaaddr_plen);
	}

	/* Address */
	if (memcpy(&iaaddr->iaaddr_addr.sin6_addr, data,
	    sizeof(iaaddr->iaaddr_addr.sin6_addr)) == NULL)
		return (-1);
	data += sizeof(iaaddr->iaaddr_addr.sin6_addr);
	iaaddr->iaaddr_addr.sin6_len = sizeof(struct sockaddr_in6);
	iaaddr->iaaddr_addr.sin6_family = PF_INET6;

	/* Preferred-Lifetime */
	if (memcpy(&iaaddr->iaaddr_pltime, data,
	    sizeof(iaaddr->iaaddr_pltime)) == NULL)
		return (-1);
	iaaddr->iaaddr_pltime = ntohl(iaaddr->iaaddr_pltime);
	data += sizeof(iaaddr->iaaddr_pltime);

	/* Valid-Lifetime */
	if (memcpy(&iaaddr->iaaddr_vltime, data,
	    sizeof(iaaddr->iaaddr_vltime)) == NULL)
		return (-1);
	iaaddr->iaaddr_vltime = ntohl(iaaddr->iaaddr_vltime);
	data += sizeof(iaaddr->iaaddr_vltime);

	if (iaaddr->iaaddr_pltime > iaaddr->iaaddr_vltime)
		return (-1);

	return (0);
}

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
	opt->option_data_len = len = DHCP6_OPTION_IANA_LEN;
	opt->option_data = calloc(DHCP6_OPTION_IANA_LEN, sizeof(uint8_t));
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
	opt->option_data_len = len = DHCP6_OPTION_IAPD_LEN;
	opt->option_data = calloc(DHCP6_OPTION_IAPD_LEN, sizeof(uint8_t));
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
dhcp6_options_add_ia_prefix(struct dhcp6_options *opts, uint8_t prefixlen)
{
	struct dhcp6_option 	*opt;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (NULL);

	opt->option_code = DHCP6_OPTION_IAPREFIX;
	opt->option_data_len = DHCP6_OPTION_IAPREFIX_LEN;
	opt->option_data = calloc(DHCP6_OPTION_IAPREFIX_LEN, sizeof(uint8_t));
	*opt->option_data = prefixlen;

	TAILQ_INIT(&opt->option_options);
	TAILQ_INSERT_TAIL(opts, opt, option_entry);

	return (&opt->option_options);
}

struct dhcp6_options *
dhcp6_options_add_ia_addr(struct dhcp6_options *opts)
{
	struct dhcp6_option 	*opt;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (NULL);

	opt->option_code = DHCP6_OPTION_IAADDR;
	opt->option_data_len = DHCP6_OPTION_IAADDR_LEN;
	opt->option_data = calloc(DHCP6_OPTION_IAADDR_LEN, sizeof(uint8_t));

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
		if (!TAILQ_EMPTY(&opt->option_options) && ++depth < 3)
			olen += dhcp6_options_get_length(&opt->option_options,
			    depth);
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
	if ((left = dhcp6_options_serialize(&buf, left, &msg->msg_options,
	    0)) == -1)
		return (-1);

	return (length - left);
}

ssize_t
dhcp6_options_serialize(uint8_t **buf, ssize_t left, struct dhcp6_options *opts,
    int depth)
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

		if (!TAILQ_EMPTY(&opt->option_options) &&
		    ++depth < DHCP6_OPTIONS_DEPTH_MAX){
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

		if (buf_get(&opt->option_length, &data,
		    sizeof(opt->option_length),
		    &length) == -1)
			goto clean;

		opt->option_length = ntohs(opt->option_length);
		if (opt->option_length > DHCP6_MSG_LEN_MAX) {
			log_debug("%s: invalid size value: %d, code: %d",
			    __func__, opt->option_length, opt->option_code);
			goto clean;
		}

		switch(opt->option_code) {
		case DHCP6_OPTION_IANA:
		case DHCP6_OPTION_IAPD:
			olen = 3 * sizeof(uint32_t);
			opt->option_data = calloc(1, olen);
			opt->option_data_len = olen;
			if (buf_get(opt->option_data, &data, olen,
			    &length) == -1)
				return (NULL);
			if (opt->option_length - olen > 0) {
				/* Recursion depth limited to 3.*/
				if (++depth == DHCP6_OPTIONS_DEPTH_MAX)
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
			if (buf_get(opt->option_data, &data, olen,
			    &length) == -1)
				return (NULL);
			if (opt->option_length - olen > 0) {
				/* Recursion depth limited to 3.*/
				if (++depth == DHCP6_OPTIONS_DEPTH_MAX)
					goto clean;
				dhcp6_options_parse(&opt->option_options,
				    data, opt->option_length - olen, depth);
				length -= opt->option_length - olen;
				data += opt->option_length - olen;
			}
			break;
		default:
			if (opt->option_length > 0 ) {
				opt->option_data = calloc(1,
				    opt->option_length);
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
