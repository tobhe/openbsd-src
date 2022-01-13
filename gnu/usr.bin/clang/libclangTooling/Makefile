LIB=	clangTooling
NOPIC=
NOPROFILE=

CPPFLAGS+=	-I ${.CURDIR}/../../../llvm/clang/lib/Tooling
CPPFLAGS+=	 ${CLANG_INCLUDES}

.include <bsd.own.mk>

SRCS+=	Refactoring.cpp \
	Replacement.cpp \


.PATH:	${.CURDIR}/../../../llvm/clang/lib/Tooling/
.PATH:	${.CURDIR}/../../../llvm/clang/lib/Tooling/Core/

install:
	@# Nothing here so far ...

.include <bsd.lib.mk>
