/*
 * Copyright (C) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _CURVE25519_H_
#define _CURVE25519_H_

#define CURVE25519_KEY_SIZE 32

void curve25519_generic(
    uint8_t [CURVE25519_KEY_SIZE],
    const uint8_t [CURVE25519_KEY_SIZE],
    const uint8_t [CURVE25519_KEY_SIZE]);

static inline void
curve25519_clamp_secret(uint8_t secret[CURVE25519_KEY_SIZE])
{
	secret[0] &= 248;
	secret[31] = (secret[31] & 127) | 64;
}

static const uint8_t null_point[CURVE25519_KEY_SIZE];

static inline int
curve25519(
    uint8_t mypublic[CURVE25519_KEY_SIZE],
    const uint8_t secret[CURVE25519_KEY_SIZE],
    const uint8_t basepoint[CURVE25519_KEY_SIZE])
{
	curve25519_generic(mypublic, secret, basepoint);
	return timingsafe_bcmp(mypublic, null_point, CURVE25519_KEY_SIZE);
}

static inline int
curve25519_generate_public(
    uint8_t pub[CURVE25519_KEY_SIZE],
    const uint8_t secret[CURVE25519_KEY_SIZE])
{
	static const uint8_t basepoint[CURVE25519_KEY_SIZE] = { 9 };
	if (timingsafe_bcmp(secret, null_point, CURVE25519_KEY_SIZE) == 0)
		return 0;
	return curve25519(pub, secret, basepoint);
}

static inline void
curve25519_generate_secret(uint8_t secret[CURVE25519_KEY_SIZE])
{
	arc4random_buf(secret, CURVE25519_KEY_SIZE);
	curve25519_clamp_secret(secret);
}

#endif /* _CURVE25519_H_ */
