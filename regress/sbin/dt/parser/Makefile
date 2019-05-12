#	$OpenBSD: Makefile,v 1.2 2017/05/30 15:36:13 bluhm Exp $

WARNINGS=Yes

PROG=		test_parser
SRCS=		tests.c
DTOBJS=		parse.o
CLEANFILES=	${DTOBJS} libtest_helper.a

LDADD+=		-lutil ${DTOBJS}
CFLAGS+=	-I${.CURDIR}/../../../../sbin/dlang
CFLAGS+=	-Wno-missing-field-initializers

test_parser: ${DTOBJS}

${DTOBJS}:
	cd ${.CURDIR}/../../../../sbin/dlang && make $@
	ln -sf ${.OBJDIR}/../../../../sbin/dlang/$@ .

LDADD+=		-L${.OBJDIR} -ltest_helper
DPADD+=		libtest_helper.a
CFLAGS+=	-I${.CURDIR}/../test_helper

libtest_helper.a:
	cd ${.CURDIR}/../test_helper && make $@
	ln -sf ${.OBJDIR}/../test_helper/$@ .

.include <bsd.regress.mk>
