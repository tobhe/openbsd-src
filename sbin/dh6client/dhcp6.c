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

#include "dhcp6.h"
#include "log.h"

#define PARSE(TO, FROM, LENGTH, SIZE) do { \
	memcpy(TO, FROM, SIZE); \
	FROM += SIZE; \
	LENGTH -= SIZE; \
	} while (0)

struct ibuf *dhcp6_options_serialize(struct ibuf *, struct dhcp6_options *);
struct dhcp6_options *
    dhcp6_options_parse(struct dhcp6_options *, uint8_t*, size_t);

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
	dhcp6_options_free(&msg->msg_options);
	free(msg);
}

void
dhcp6_options_free(struct dhcp6_options *opts)
{
	struct dhcp6_option	*opt, *tmp;

	TAILQ_FOREACH_SAFE(opt, opts, option_entry, tmp) {
		if (!TAILQ_EMPTY(&opt->option_options))
			dhcp6_options_free(&opt->option_options);
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

size_t
dhcp6_options_get_length(struct dhcp6_options *opts)
{
	struct dhcp6_option	*opt;
	size_t			 len = 0, olen;

	TAILQ_FOREACH(opt, opts, option_entry) {
		olen = 0;
		if (!TAILQ_EMPTY(&opt->option_options))
			olen += dhcp6_options_get_length(&opt->option_options);
		opt->option_length = opt->option_data_len + olen;
		len += opt->option_length + 4;
	}
	return len;
}

#define DH6CLIENT_MSGBUF_MAX	(8192)

struct ibuf *
dhcp6_msg_serialize(struct dhcp6_msg *msg)
{
	struct ibuf		*buf;

 	if ((buf = ibuf_dynamic(0, DH6CLIENT_MSGBUF_MAX)) == NULL)
 		return (NULL);
	explicit_bzero(ibuf_seek(buf, 0, 0), buf->wpos);

	/* Message Header */
	if (ibuf_add(buf, &msg->msg_type, sizeof(msg->msg_type)) == -1)
		goto err;
	if (ibuf_add(buf, &msg->msg_transaction_id,
	    sizeof(msg->msg_transaction_id)) == -1)
		goto err;

	/* Calculate list lengths */
	dhcp6_options_get_length(&msg->msg_options);

	/* Options */
	return (dhcp6_options_serialize(buf, &msg->msg_options));
 err:
	ibuf_free(buf);
	return (NULL);
}

struct ibuf *
dhcp6_options_serialize(struct ibuf *buf, struct dhcp6_options *opts)
{
	struct dhcp6_option	*opt;
	uint16_t		 h;

	/* Options */
	TAILQ_FOREACH(opt, opts, option_entry) {
		h = htons(opt->option_code);
		if (ibuf_add(buf, &h, sizeof(h)) == -1)
			goto err;
		h = htons(opt->option_length);
		if (ibuf_add(buf, &h, sizeof(h)) == -1)
			goto err;
		if (ibuf_add(buf, opt->option_data, opt->option_data_len) == -1)
			goto err;

		if (!TAILQ_EMPTY(&opt->option_options)){
			if (dhcp6_options_serialize(buf, &opt->option_options) == NULL)
				goto err;
		}
	}
	return (buf);
 err:
	ibuf_free(buf);
	return (NULL);
}

struct dhcp6_msg *
dhcp6_msg_parse(uint8_t* data, size_t length)
{
	struct dhcp6_msg	*msg;

	msg = calloc(1, sizeof(*msg));
	TAILQ_INIT(&msg->msg_options);

	/* Header */
	PARSE(&msg->msg_type, data, length, sizeof(msg->msg_type));
	PARSE(msg->msg_transaction_id, data, length, sizeof(msg->msg_transaction_id));

	/* Options */
	if (dhcp6_options_parse(&msg->msg_options, data, length) == NULL) {
		printf("Failed to parse options.\n");
		free(msg);
		return (NULL);
	}
	return (msg);
}

struct dhcp6_options *
dhcp6_options_parse(struct dhcp6_options *opts, uint8_t* data, size_t length)
{
	struct dhcp6_option	*opt;
	size_t			 olen;

	while (length) {
		if ((opt = calloc(1, sizeof(*opt))) == NULL) {
			printf("Failed calloc.\n");
			return (NULL);
		}
		TAILQ_INIT(&opt->option_options);

		PARSE(&opt->option_code, data, length, sizeof(opt->option_code));
		opt->option_code = ntohs(opt->option_code);

		PARSE(&opt->option_length, data, length, sizeof(opt->option_length));
		opt->option_length = ntohs(opt->option_length);

		switch(opt->option_code) {
		case DHCP6_OPTION_IANA:
			olen = 3 * sizeof(uint32_t);
			opt->option_data = calloc(1, olen);
			opt->option_data_len = olen;
			PARSE(opt->option_data, data, length, olen);
			if (opt->option_length - olen > 0) {
				dhcp6_options_parse(&opt->option_options,
				    data, opt->option_length - olen);
				length -= opt->option_length - olen;
				data += opt->option_length - olen;
			}
			break;
		default:
			if (opt->option_length) {
				opt->option_data = calloc(1, opt->option_length);
				opt->option_data_len = opt->option_length;
				PARSE(opt->option_data, data, length, opt->option_length);
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

