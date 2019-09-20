/*	$OpenBSD$	*/

/*
 * Copyright (c) 2019 Tobias Heider <tobhe@openbsd.org>
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/queue.h>
#include <sys/uio.h>

#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include <imsg.h>
#include <inttypes.h>
#include <unistd.h>

#include "dhcp6.h"
#include "dh6client.h"

int
test_parser(void)
{
	char			 buf[1500];
	ssize_t			 len;
	struct dhcp6_msg	*msg;

	if ((len = read(STDIN_FILENO, buf, 1500)) == 0) {
		log_warn("%s: failed to read from stdin.", __func__);
		return (-1);
	}

	log_info("%s: Input length: %zd", __func__, len);
	if ((msg = dhcp6_msg_parse(buf, len)) == NULL) {
		log_warn("%s: failed to parse packet.", __func__);
		return (-1);
	}
	log_info("Parse_result\n");
	dhcp6_msg_print(msg);
	dhcp6_msg_free(msg);
	return 0;
}


void
print_debug(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vfprintf(stderr, emsg, ap);
	va_end(ap);
}

void
print_hex(uint8_t *buf,  off_t offset, size_t length)
{
	unsigned int	 i;

	for (i = 0; i < length; i++) {
		if (i && (i % 4) == 0) {
			if ((i % 32) == 0)
				print_debug("\n");
			else
				print_debug(" ");
		}
		print_debug("%02x", buf[offset + i]);
	}
	print_debug("\n");
}

