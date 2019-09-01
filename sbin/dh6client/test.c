#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <stdio.h>
#include <strings.h>
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
	ssize_t			 len;
	struct dhcp6_options	*opts;

	buf = ibuf_open(1500);

	msg = dhcp6_msg_init(1);

	dhcp6_options_add_option(&msg->msg_options, 1, "test", sizeof("test"));
	dhcp6_options_add_option(&msg->msg_options, 2, "lolwut", sizeof("lolwut"));
	dhcp6_options_add_option(&msg->msg_options, 7, "waddafack", sizeof("waddafack"));
	opts = dhcp6_options_add_iana(&msg->msg_options, 0, 0, 0);
	dhcp6_options_add_option(opts, 7, "waddafack", sizeof("waddafack"));
	dhcp6_options_add_option(opts, 2, "lolwut", sizeof("lolwut"));
	dhcp6_options_add_option(&msg->msg_options, 2, "lolwut", sizeof("lolwut"));
	dhcp6_msg_print(msg);
	if ((len = dhcp6_msg_serialize(msg, ibuf_seek(buf, 0, 0), ibuf_left(buf))) == -1)
		return (-1);
	dhcp6_msg_print(msg);
	dhcp6_msg_free(msg);
	print_hex(ibuf_seek(buf, 0, 0), 0, len);

	msg = dhcp6_msg_parse(ibuf_seek(buf, 0, 0), len);
	printf("Parse_result\n");
	dhcp6_msg_print(msg);
	dhcp6_msg_free(msg);

	return 0;
}
