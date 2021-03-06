/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_EDDSA_H
#define _FIDO_EDDSA_H

#include <openssl/ec.h>

#include <stdint.h>
#include <stdlib.h>

#ifdef _FIDO_INTERNAL
#include "types.h"
#else
#include <fido.h>
#endif

eddsa_pk_t *eddsa_pk_new(void);
void eddsa_pk_free(eddsa_pk_t **);
EVP_PKEY *eddsa_pk_to_EVP_PKEY(const eddsa_pk_t *);

int eddsa_pk_from_EVP_PKEY(eddsa_pk_t *, const EVP_PKEY *);
int eddsa_pk_from_ptr(eddsa_pk_t *, const void *, size_t);

#ifdef _FIDO_INTERNAL

#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10101000L
#define EVP_PKEY_ED25519 EVP_PKEY_NONE
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *, unsigned char *, size_t *);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int, ENGINE *, const unsigned char *,
    size_t);
int EVP_DigestVerify(EVP_MD_CTX *, const unsigned char *, size_t,
    const unsigned char *, size_t);
#endif /* LIBRESSL_VERSION_NUMBER || OPENSSL_VERSION_NUMBER < 0x10101000L */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);
#endif

#endif /* _FIDO_INTERNAL */

#endif /* !_FIDO_EDDSA_H */
