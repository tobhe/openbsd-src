/*	$OpenBSD: dh.h,v 1.11 2017/10/27 14:26:35 patrick Exp $	*/

/*
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
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

#ifndef DH_GROUP_H
#define DH_GROUP_H

enum group_type {
	GROUP_MODP		= 0,
	GROUP_EC2N		= 1,
	GROUP_ECP		= 2,
	GROUP_CURVE25519	= 3,
#ifdef OQS
	GROUP_SIDH		= 4,
#endif
};

struct group_id {
	enum group_type	 type;
	unsigned int	 id;
	int		 bits;
	char		*prime;
	char		*generator;
	int		 nid;
};

struct group {
	int		 id;
	const struct group_id
			*spec;

	void		*dh;
	void		*ec;
	void		*curve25519;
#ifdef OQS
	void		*pq;
#endif

	int		(*init)(struct group *);
	int		(*getlen)(struct group *);
	int		(*secretlen)(struct group *);
	int		(*exchange)(struct group *, uint8_t *);
	int		(*exchange2)(struct group *, struct ibuf**, struct ibuf *);
	int		(*shared)(struct group *, uint8_t *, uint8_t *);
	int		(*shared2)(struct group *, struct ibuf **, struct ibuf *);
};

#define DH_MAXSZ	1024	/* 8192 bits */

void		 group_init(void);
void		 group_free(struct group *);
struct group	*group_get(uint32_t);
const struct group_id
		*group_getid(uint32_t);

int		 dh_create_exchange(struct group *, struct ibuf **, struct ibuf *);
int		 dh_create_shared(struct group *, struct ibuf **, struct ibuf *);

#endif /* DH_GROUP_H */
