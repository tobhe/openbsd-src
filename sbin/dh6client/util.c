#include <stdio.h>

#include "dh6client.h"


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

