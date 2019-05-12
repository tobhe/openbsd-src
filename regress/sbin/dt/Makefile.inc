
CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Wextra
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wpointer-sign
CDIAGFLAGS+=	-Wno-unused-parameter
CDIAGFLAGS+=	-Wuninitialized
.if (${CC:L} == "gcc" || ${CC:L} == "cc")
.endif

DEBUG=	-g
