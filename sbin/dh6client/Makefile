#	$OpenBSD$

PROG=	dh6client
SRCS=	dh6client.c frontend.c log.c dhcp6.c engine.c

MAN=	slaacd.8

#DEBUG=	-g -DDEBUG=3 -O0

CFLAGS+= -g -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+=	-levent -lutil
DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
