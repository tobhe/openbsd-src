#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <stdio.h>
#include <assert.h>
#include <imsg.h>
#include <inttypes.h>

#include "dhcp6.h"
#include "dh6client.h"

int
test_parser(void)
{
	struct dhcp6_msg	*msg;
	struct ibuf		*buf;
	uint8_t			*data;
	size_t			 i;

	msg = dhcp6_msg_init(1);
	buf = dhcp6_msg_serialize(msg);

	dhcp6_msg_print(msg);

	data = ibuf_seek(buf, 0, 0);
	for (i = 0; i < ibuf_size(buf); i++) {
		printf("%02"PRIx8, data[i]);
	}
	printf("\n");

	dhcp6_msg_add_option(msg, 1, "test", sizeof("test"));
	if ((buf = dhcp6_msg_serialize(msg)) == NULL) {
		printf("Error in serializer.");
		return (-1);
	}

	dhcp6_msg_add_option(msg, 2, "lolwut", sizeof("lolwut"));
	if ((buf = dhcp6_msg_serialize(msg)) == NULL) {
		printf("Error in serializer.");
		return (-1);
	}

	dhcp6_msg_print(msg);

	data = ibuf_seek(buf, 0, 0);
	for (i = 0; i < ibuf_size(buf); i++) {
		printf("%02"PRIx8, data[i]);
	}
	printf("\n");

	msg = dhcp6_msg_parse(data, ibuf_size(buf));
	dhcp6_msg_print(msg);

	return 0;
}
