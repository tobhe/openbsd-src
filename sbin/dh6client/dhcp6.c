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

struct dhcp6_option {
	uint16_t			 option_code;
	uint16_t			 option_length;
	uint8_t				*option_data;
	SLIST_ENTRY(dhcp6_option)	 option_entry;
};

void
dhcp6_msg_print(struct dhcp6_msg *msg)
{
	struct dhcp6_option	*opt;
	size_t			 i;

	printf("Print DHCPv6 Message:\n");
	printf("\tMessage Type:\t%"PRIu8"\n", msg->msg_type);
	printf("\tMessage Transaction ID:\t");
	for (i = 0; i < sizeof(msg->msg_transaction_id); i++) {
		printf("%02"PRIx8, msg->msg_transaction_id[i]);
	}
	printf("\n");
	SLIST_FOREACH(opt, &msg->msg_options, option_entry) {
		printf("\tOption Code:\t%"PRIu16"\n", opt->option_code);
		printf("\tOption Length:\t%"PRIu16"\n", opt->option_length);
		printf("\tOption Data:\t");
		for (i = 0; i < opt->option_length; i++) {
			printf("%02"PRIx8, opt->option_data[i]);
		}
		printf("\n");
	}
}

struct dhcp6_msg *
dhcp6_msg_init(uint8_t type)
{
	struct dhcp6_msg	*msg;

	if ((msg = calloc(1, sizeof(*msg))) == NULL)
		return NULL;

	msg->msg_type = type;
	arc4random_buf(msg->msg_transaction_id, sizeof(msg->msg_transaction_id));
	SLIST_INIT(&msg->msg_options);

	return msg;
}

int
dhcp6_msg_add_option(struct dhcp6_msg *msg, int code, uint8_t *data,
    size_t length)
{
	struct dhcp6_option *opt;

	if ((opt = calloc(1, sizeof(struct dhcp6_option))) == NULL)
		return (-1);

	opt->option_data = data;
	opt->option_code = code;
	opt->option_length = length;

	SLIST_INSERT_HEAD(&msg->msg_options, opt, option_entry);

	return (0);
}

#define DH6CLIENT_MSGBUF_MAX	(8192)

struct ibuf *
dhcp6_msg_serialize(struct dhcp6_msg *msg)
{
	struct dhcp6_option	*opt;
	struct ibuf		*buf;
	uint16_t		 h;

 	if ((buf = ibuf_dynamic(0, DH6CLIENT_MSGBUF_MAX)) == NULL)
 		return (NULL);
	explicit_bzero(ibuf_seek(buf, 0, 0), buf->wpos);

	/* Message Header */
	if (ibuf_add(buf, &msg->msg_type, sizeof(msg->msg_type)) == -1)
		goto err;

	if (ibuf_add(buf, &msg->msg_transaction_id, sizeof(msg->msg_transaction_id)) == -1)
		goto err;

	/* Options */
	SLIST_FOREACH(opt, &msg->msg_options, option_entry) {
		h = htons(opt->option_code);
		if (ibuf_add(buf, &h, sizeof(h)) == -1)
			goto err;
		h = htons(opt->option_length);
		if (ibuf_add(buf, &h, sizeof(h)) == -1)
			goto err;
		if (ibuf_add(buf, opt->option_data, opt->option_length) == -1)
			goto err;
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
	struct dhcp6_option	*opt;

	msg = calloc(1, sizeof(*msg));

	/* Header */
	PARSE(&msg->msg_type, data, length, sizeof(msg->msg_type));
	PARSE(msg->msg_transaction_id, data, length, sizeof(msg->msg_transaction_id));

	/* Options */
	while (length > 4) {
		opt = calloc(1, sizeof(*opt));
		PARSE(&opt->option_code, data, length, sizeof(opt->option_code));
		opt->option_code = ntohs(opt->option_code);

		PARSE(&opt->option_length, data, length, sizeof(opt->option_length));
		opt->option_length = ntohs(opt->option_length);

		if (opt->option_length) {
			opt->option_data = calloc(1, opt->option_length);
			PARSE(opt->option_data, data, length, opt->option_length);
		}
		SLIST_INSERT_HEAD(&msg->msg_options, opt, option_entry);
	}
	return (msg);
}

int
dhcp6_get_duid(struct ether_addr *mac,
    uint8_t type, struct dhcp6_duid *duid)
{
	struct dhcp6_duid_llpt		*llpt;
	size_t				 len;
	uint64_t			 t;
	int				 ret = -1;

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

