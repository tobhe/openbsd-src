#!/bin/sh
#       $OpenBSD$
#       Placed in the Public Domain.
#
AUTHOR="kyber-3.0/AUTHORS"
FILES="
	kyber-3.0/ref/params.h
	kyber-3.0/ref/poly.h
	kyber-3.0/ref/polyvec.h
	kyber-3.0/ref/cbd.h
	kyber-3.0/ref/fips202.h
	kyber-3.0/ref/indcpa.h
	kyber-3.0/ref/kem.h
	kyber-3.0/ref/ntt.h
	kyber-3.0/ref/reduce.h
	kyber-3.0/ref/symmetric.h
	kyber-3.0/ref/verify.h
	kyber-3.0/ref/cbd.c
	kyber-3.0/ref/fips202.c
	kyber-3.0/ref/indcpa.c
	kyber-3.0/ref/kem.c
	kyber-3.0/ref/ntt.c
	kyber-3.0/ref/poly.c
	kyber-3.0/ref/polyvec.c
	kyber-3.0/ref/reduce.c
	kyber-3.0/ref/symmetric-shake.c
	kyber-3.0/ref/verify.c
"
###

set -e
cd $1
echo -n '/*  $'
echo 'OpenBSD: $ */'
echo
echo '/*'
echo ' * Public Domain, Authors:'
sed -e 's/^/ * - /' < $AUTHOR
echo ' */'
echo
echo '#include <string.h>'
echo '#include "crypto_api.h"'
echo
# Map the types used in this code to the ones in crypto_api.h.  We use #define
# instead of typedef since some systems have existing intXX types and do not
# permit multiple typedefs even if they do not conflict.
for t in int8 uint8 int16 uint16 int32 uint32 int64 uint64; do
	echo "#define $t crypto_${t}"
done
echo
for i in $FILES; do
	echo "/* from $i */"
	# Changes to all files:
	#  - remove all includes, we inline everything required.
	#  - make functions not required elsewhere static.
	#  - rename the functions we do use.
	#  - remove unnecessary defines and externs.
	sed -e "/#include/d" \
	    -e "s/crypto_kem_/crypto_kem_kyber768_/g" \
	    -e "s/^void /static void /g" \
	    -e "s/^int16 /static int16 /g" \
	    -e "s/^uint16 /static uint16 /g" \
	    -e "/^extern /d" \
	    -e '/define.*_NAMESPACE/d' \
	    -e "/^#define int32 crypto_int32/d" \
	    -e 's/[	 ]*$//' \
	    $i | \
	case "$i" in
	# Remove unused function to prevent warning.
	*/ref/fips202.c)
	    sed \
		-e '/int keccak_absorb(/,/^}$/d' \
		-e '/void keccak_finalize(.*)$/,/^$/d' \
		-e '/void keccak_init(.*)$/,/^$/d' \
		-e '/void shake128(.*)$/,/^}$/d' \
		-e '/void shake128_absorb(.*)$/,/^$/d' \
		-e '/void shake128_finalize(.*)$/,/^$/d' \
		-e '/void shake128_init(.*)$/,/^$/d' \
		-e '/void shake128_squeeze(.*)$/,/^$/d' \
		-e '/void shake256_absorb(.*)$/,/^$/d' \
		-e '/void shake256_finalize(.*)$/,/^$/d' \
		-e '/void shake256_init(.*)$/,/^$/d'
	    ;;
	*/ref/fips202.h)
	    sed \
		-e '/void keccak_finalize(/d' \
		-e '/void keccak_init(/d' \
		-e '/void shake128(/d' \
		-e '/void shake128_absorb(/d' \
		-e '/void shake128_finalize(/d' \
		-e '/void shake128_init(/d' \
		-e '/void shake128_squeeze(/d' \
		-e '/void shake256_absorb(/d' \
		-e '/void shake256_finalize(/d' \
		-e '/void shake256_init(/d'
	    ;;
	# Default: pass through.
	*)
	    cat
	    ;;
	esac
	echo
done
