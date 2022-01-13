LIB=	clangIndex
NOPIC=
NOPROFILE=

CPPFLAGS+=	-I ${.CURDIR}/../../../llvm/clang/lib/Index
CPPFLAGS+=	 ${CLANG_INCLUDES}

.include <bsd.own.mk>

SRCS+=	CommentToXML.cpp \
	USRGeneration.cpp \

.PATH:	${.CURDIR}/../../../llvm/clang/lib/Index/

install:
	@# Nothing here so far ...

.include <bsd.lib.mk>
