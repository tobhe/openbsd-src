LIB=	clangCrossTU
NOPIC=
NOPROFILE=

CPPFLAGS+=	-I ${.CURDIR}/../../../llvm/clang/lib/CrossTU
CPPFLAGS+=	 ${CLANG_INCLUDES}

.include <bsd.own.mk>

SRCS+=	CrossTranslationUnit.cpp \

.PATH:	${.CURDIR}/../../../llvm/clang/lib/CrossTU/

install:
	@# Nothing here so far ...

.include <bsd.lib.mk>
