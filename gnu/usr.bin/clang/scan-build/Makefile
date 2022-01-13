# $OpenBSD$

.include <bsd.own.mk>

LIBEXECDIR= /usr/libexec
BINDIR= /usr/bin

SRCDIR= ${.CURDIR}/../../../llvm/clang/tools/scan-build

SCRIPTS=		scan-build

LIBEXEC_SCRIPTS=	c++-analyzer \
			ccc-analyzer \

SHARE_FILES=		scanview.css \
			sorttable.js \

realinstall:
.for i in ${SCRIPTS}
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
	    ${SRCDIR}/bin/$i ${DESTDIR}${BINDIR}/$i
.endfor
.for i in ${LIBEXEC_SCRIPTS}
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
	    ${SRCDIR}/libexec/$i ${DESTDIR}${LIBEXECDIR}/$i
.endfor
.for i in ${SHARE_FILES}
	${INSTALL} ${INSTALL_COPY} -o ${SHAREOWN} -g ${SHAREGRP} -m ${SHAREMODE} \
	    ${SRCDIR}/share/scan-build/$i ${DESTDIR}${SHAREDIR}/scan-build/$i
.endfor

.include <bsd.prog.mk>
