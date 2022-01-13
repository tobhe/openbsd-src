LIB=	clangASTMatchers
NOPIC=
NOPROFILE=

CPPFLAGS+=	 ${CLANG_INCLUDES}

.include <bsd.own.mk>

# Core
SRCS+=	ASTMatchFinder.cpp \
	ASTMatchersInternal.cpp \
	GtestMatchers.cpp \
	Diagnostics.cpp \
	Marshallers.cpp \
	Parser.cpp \
	Registry.cpp \
	VariantValue.cpp \

.PATH:	${.CURDIR}/../../../llvm/clang/lib/ASTMatchers
.PATH:	${.CURDIR}/../../../llvm/clang/lib/ASTMatchers/Dynamic

install:
	@# Nothing here so far ...

.include <bsd.lib.mk>
