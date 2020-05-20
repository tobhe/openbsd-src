/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
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

#include "bpfilter.h"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/pool.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/percpu.h>
#include <sys/ioctl.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_wg.h>

#include <net/pfvar.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/in_pcb.h>

#include <crypto/wg_noise.h>
#include <crypto/wg_cookie.h>
#include <crypto/siphash.h>

#define DEFAULT_MTU		1420

#define MAX_STAGED_PKT		128
#define MAX_QUEUED_PKT		512
#define MAX_QUEUED_PKT_MASK	(MAX_QUEUED_PKT - 1)

#define MAX_QUEUED_HANDSHAKES	256

#define HASHTABLE_PEER_SIZE	(1 << 6)
#define HASHTABLE_INDEX_SIZE	(HASHTABLE_PEER_SIZE * 3)
#define MAX_PEERS_PER_IFACE	(1 << 20)

#define REKEY_TIMEOUT		5
#define REKEY_TIMEOUT_JITTER	334 /* 1/3 sec, round for arc4random_uniform */
#define KEEPALIVE_TIMEOUT	10
#define MAX_TIMER_HANDSHAKES	(90 / REKEY_TIMEOUT)
#define NEW_HANDSHAKE_TIMEOUT	(REKEY_TIMEOUT + KEEPALIVE_TIMEOUT)
#define UNDERLOAD_TIMEOUT	1

#define DPRINTF(sc, str, ...) do { if (ISSET((sc)->sc_if.if_flags, IFF_DEBUG))\
    printf("%s: " str, (sc)->sc_if.if_xname, ##__VA_ARGS__); } while (0)

#define WG_PEERS_FOREACH(p, sc, i)				\
	for (i = 0; i <= (sc)->sc_peer_mask; i++)		\
		LIST_FOREACH(p, &(sc)->sc_peer[i], p_entry)

#define WG_PEERS_FOREACH_SAFE(p, sc, i, tp)			\
	for (i = 0; i <= (sc)->sc_peer_mask; i++)		\
		LIST_FOREACH_SAFE(p, &(sc)->sc_peer[i], p_entry, tp)

#define CONTAINER_OF(ptr, type, member) ({			\
	const __typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

/* First byte indicating packet type on the wire */
#define WG_PKT_INITIATION htole32(1)
#define WG_PKT_RESPONSE htole32(2)
#define WG_PKT_COOKIE htole32(3)
#define WG_PKT_DATA htole32(4)

#define WG_PKT_PADDING(n) ((-(n)) & (16 - 1))
#define WG_KEY_SIZE WG_KEY_LEN

/* Packet */
struct wg_pkt_initiation {
	uint32_t		t;
	struct noise_initiation init;
	struct cookie_macs	m;
} __packed;

struct wg_pkt_response {
	uint32_t		t;
	struct noise_response	resp;
	struct cookie_macs	m;
} __packed;

struct wg_pkt_cookie {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[COOKIE_XNONCE_SIZE];
	uint8_t			ec[COOKIE_ENCRYPTED_SIZE];
} __packed;

struct wg_pkt_data {
	uint32_t		t;
	struct noise_data	data;
} __packed;

struct wg_endpoint {
	union {
		struct sockaddr		r_sa;
		struct sockaddr_in	r_sin;
		struct sockaddr_in6	r_sin6;
	} e_remote;
	union {
		struct in_addr		l_in;
		struct in6_pktinfo	l_pktinfo6;
#define l_in6 l_pktinfo6.ipi6_addr
	} e_local;
};

struct wg_tag {
	struct wg_endpoint	 t_endpoint;
	struct wg_peer		*t_peer;
	struct mbuf		*t_mbuf;
	int			 t_done;
};

struct wg_index {
	LIST_ENTRY(wg_index)	 i_entry;
	SLIST_ENTRY(wg_index)	 i_unused_entry;
	uint32_t		 i_key;
	struct noise_remote	*i_value;
};

struct wg_timers {
	/* t_lock is for blocking wg_timers_event_* when setting t_disabled. */
	struct rwlock		 t_lock;

	int			 t_disabled;
	int			 t_need_another_keepalive;
	uint16_t		 t_persistent_keepalive_interval;
	struct timeout		 t_new_handshake;
	struct timeout		 t_send_keepalive;
	struct timeout		 t_retry_handshake;
	struct timeout		 t_zero_key_material;
	struct timeout		 t_persistent_keepalive;

	struct mutex		 t_handshake_mtx;
	struct timeval		 t_handshake_touch;	/* microuptime */
	struct timespec		 t_handshake_complete;	/* nanotime */
	int			 t_handshake_retries;

	struct wg_timers_fn	*t_fn; /* not locked/mutex'd */
};

struct wg_timers_fn {
	void (*f_send_initiation)(struct wg_timers *, int, int);
	void (*f_send_keepalive)(struct wg_timers *);
	void (*f_clear_secrets)(struct wg_timers *);
	void (*f_clear_staged)(struct wg_timers *);
	void (*f_clear_src)(struct wg_timers *);
};

struct wg_aip {
	struct art_node		 a_node;
	SLIST_ENTRY(wg_aip)	 a_entry;
	struct wg_peer		*a_peer;
	struct wg_aip_data	 a_data;
};

struct wg_queue {
	struct mutex		 q_mtx;
	struct mbuf_list	 q_list;
};

struct wg_ring {
	struct mutex	 r_mtx;
	uint32_t	 r_head;
	uint32_t	 r_tail;
	struct mbuf	*r_buf[MAX_QUEUED_PKT];
};

struct wg_peer {
	LIST_ENTRY(wg_peer)	 p_entry;
	uint64_t		 p_id;
	struct wg_softc		*p_sc;

	struct noise_remote	 p_remote;
	struct cookie_maker	 p_cookie;
	struct wg_timers	 p_timers;

	struct mutex		 p_counters_mtx;
	uint64_t		 p_counters_tx;
	uint64_t		 p_counters_rx;

	struct mutex		 p_endpoint_mtx;
	struct wg_endpoint	 p_endpoint;

	struct task		 p_send_initiation;
	struct task		 p_clear_secrets;
	struct task		 p_deliver_out;
	struct task		 p_deliver_in;

	struct mbuf_queue	 p_stage_queue;
	struct wg_queue		 p_encap_queue;
	struct wg_queue		 p_decap_queue;

	SLIST_HEAD(,wg_index)	 p_unused_index;
	struct wg_index		 p_index[3];

	SLIST_HEAD(,wg_aip)	 p_aip;

	SLIST_ENTRY(wg_peer)	 p_start_list;
	int			 p_start_onlist;
};

struct wg_softc {
	struct ifnet		 sc_if;
	SIPHASH_KEY		 sc_secret;

	struct rwlock		 sc_lock;
	struct noise_local	 sc_local;
	struct cookie_checker	 sc_cookie;
	in_port_t		 sc_udp_port;
	int			 sc_udp_rtable;

	struct rwlock		 sc_so_lock;
	struct socket		*sc_so4;
	struct socket		*sc_so6;

	size_t			 sc_aip_num;
	struct art_root		*sc_aip4;
	struct art_root		*sc_aip6;

	struct rwlock		 sc_peer_lock;
	size_t			 sc_peer_num;
	LIST_HEAD(,wg_peer)	*sc_peer;
	u_long			 sc_peer_mask;

	struct rwlock		 sc_index_lock;
	LIST_HEAD(,wg_index)	*sc_index;
	u_long			 sc_index_mask;

	struct task		 sc_handshake;
	struct mbuf_queue	 sc_handshake_queue;

	struct task		 sc_encap;
	struct task		 sc_decap;
	struct wg_ring		 sc_encap_ring;
	struct wg_ring		 sc_decap_ring;

	struct task		 sc_up;
	struct task		 sc_down;
};

/* wg_peer */
struct wg_peer *
	wg_peer_create(struct wg_softc *, uint8_t[WG_KEY_SIZE]);
struct wg_peer *
	wg_peer_lookup(struct wg_softc *, const uint8_t[WG_KEY_SIZE]);
void	wg_peer_destroy(struct wg_peer *);
void	wg_peer_set_endpoint_from_tag(struct wg_peer *, struct wg_tag *);
void	wg_peer_set_sockaddr(struct wg_peer *, struct sockaddr *);
int	wg_peer_get_sockaddr(struct wg_peer *, struct sockaddr *);
void	wg_peer_clear_src(struct wg_peer *);
void	wg_peer_get_endpoint(struct wg_peer *, struct wg_endpoint *);
void	wg_peer_counters_add(struct wg_peer *, uint64_t, uint64_t);

/* allowedips */
int	wg_aip_add(struct wg_softc *, struct wg_peer *, struct wg_aip_data *);
struct wg_peer *
	wg_aip_lookup(struct art_root *, void *);
int	wg_aip_remove(struct wg_softc *, struct wg_peer *,
	    struct wg_aip_data *);

/* wg_socket */
int	wg_bind(struct wg_softc *);
void	wg_unbind(struct wg_softc *);
int	wg_send(struct wg_softc *, struct wg_endpoint *, struct mbuf *);
int	wg_send_buf(struct wg_softc *, struct wg_endpoint *, uint8_t *,
	    size_t);

/* wg_tag */
struct wg_tag *
	wg_tag_get(struct mbuf *);

/* Timers */
void	wg_timers_init(struct wg_timers *, struct wg_timers_fn *);
void	wg_timers_enable(struct wg_timers *);
void	wg_timers_disable(struct wg_timers *);
void	wg_timers_set_persistent_keepalive(struct wg_timers *, uint16_t);
int	wg_timers_get_persistent_keepalive(struct wg_timers *, uint16_t *);
void	wg_timers_get_last_handshake(struct wg_timers *, struct timespec *);

void	wg_timers_event_data_sent(struct wg_timers *);
void	wg_timers_event_data_received(struct wg_timers *);
void	wg_timers_event_any_authenticated_packet_sent(struct wg_timers *);
void	wg_timers_event_any_authenticated_packet_received(struct wg_timers *);
void	wg_timers_event_handshake_initiated(struct wg_timers *);
void	wg_timers_event_handshake_responded(struct wg_timers *);
void	wg_timers_event_handshake_complete(struct wg_timers *);
void	wg_timers_event_session_derived(struct wg_timers *);
void	wg_timers_event_any_authenticated_packet_traversal(struct wg_timers *);
void	wg_timers_event_want_initiation(struct wg_timers *);

void	wg_timers_run_new_handshake(struct wg_timers *);
void	wg_timers_run_send_keepalive(struct wg_timers *);
void	wg_timers_run_retry_handshake(struct wg_timers *);
void	wg_timers_run_zero_key_material(struct wg_timers *);
void	wg_timers_run_persistent_keepalive(struct wg_timers *);

void	wg_timers_peer_send_initiation(struct wg_timers *, int, int);
void	wg_timers_peer_send_keepalive(struct wg_timers *);
void	wg_timers_peer_clear_secrets(struct wg_timers *);
void	wg_timers_peer_clear_staged(struct wg_timers *);
void	wg_timers_peer_clear_src(struct wg_timers *);

/* handshake */
int	wg_peer_send_buf(struct wg_peer *, uint8_t *, size_t);
int	wg_send_initiation(struct wg_peer *);
int	wg_send_response(struct wg_peer *);
int	wg_send_cookie(struct wg_softc *, struct cookie_macs *, uint32_t,
	    struct wg_endpoint *e);
void	wg_handshake(struct wg_softc *, struct mbuf *);
void	wg_handshake_worker(struct wg_softc *);

/* io */
void	wg_encap(struct wg_softc *, struct mbuf *);
void	wg_decap(struct wg_softc *, struct mbuf *);
void	wg_encap_worker(struct wg_softc *);
void	wg_decap_worker(struct wg_softc *);
void	wg_deliver_out(struct wg_peer *);
void	wg_deliver_in(struct wg_peer *);

/* ring */
int	wg_queue_in(struct wg_softc *, struct wg_peer *, struct mbuf *);
void	wg_queue_out(struct wg_softc *, struct wg_peer *);
struct mbuf *
	wg_ring_dequeue(struct wg_ring *);
struct mbuf *
	wg_queue_dequeue(struct wg_queue *, struct wg_tag **);
size_t	wg_queue_len(struct wg_queue *);

/* index */
struct noise_remote *
	wg_remote_get(struct wg_softc *, uint8_t[NOISE_KEY_SIZE]);
uint32_t
	wg_index_set(struct wg_softc *, struct noise_remote *);
struct noise_remote *
	wg_index_get(struct wg_softc *, uint32_t);
void	wg_index_drop(struct wg_softc *, uint32_t);

/* device */
struct mbuf *
	wg_input(void *, struct mbuf *, struct ip *, struct ip6_hdr *, void *,
	    int);
int	wg_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
int	wg_ioctl_set(struct wg_softc *, struct wg_data_io *);
int	wg_ioctl_get(struct wg_softc *, struct wg_data_io *);
int	wg_ioctl(struct ifnet *, u_long, caddr_t);
void	wg_up(struct wg_softc *);
void	wg_down(struct wg_softc *);

int	wg_clone_create(struct if_clone *, int);
int	wg_clone_destroy(struct ifnet *);
void	wgattach(int);

/* globals */
uint64_t	peer_counter = 0;
uint64_t	keypair_counter = 0;
struct pool	wg_aip_pool;
struct pool	wg_peer_pool;
struct pool	wg_ratelimit_pool;
struct timeval	rekey_interval = { REKEY_TIMEOUT, 0 };
struct timeval	underload_interval = { UNDERLOAD_TIMEOUT, 0 };

size_t		 wg_counter = 0;
struct taskq	*wg_handshake_taskq;
struct taskq	*wg_crypt_taskq;

struct wg_timers_fn wg_timers_wg_fn = {
	.f_send_initiation = wg_timers_peer_send_initiation,
	.f_send_keepalive = wg_timers_peer_send_keepalive,
	.f_clear_secrets = wg_timers_peer_clear_secrets,
	.f_clear_staged = wg_timers_peer_clear_staged,
	.f_clear_src = wg_timers_peer_clear_src,
};

struct if_clone	wg_cloner =
    IF_CLONE_INITIALIZER("wg", wg_clone_create, wg_clone_destroy);

/* functions */
struct wg_peer *
wg_peer_create(struct wg_softc *sc, uint8_t public[WG_KEY_SIZE])
{
	struct wg_peer	*peer;
	uint64_t	 idx;

	rw_assert_wrlock(&sc->sc_lock);

	if (sc->sc_peer_num >= MAX_PEERS_PER_IFACE)
		return NULL;

	if ((peer = pool_get(&wg_peer_pool, PR_NOWAIT)) == NULL)
		return NULL;

	peer->p_id = peer_counter++;
	peer->p_sc = sc;

	noise_remote_init(&peer->p_remote, public, &sc->sc_local);
	cookie_maker_init(&peer->p_cookie, public);
	wg_timers_init(&peer->p_timers, &wg_timers_wg_fn);

	mtx_init(&peer->p_counters_mtx, IPL_NET);
	peer->p_counters_tx = 0;
	peer->p_counters_rx = 0;

	mtx_init(&peer->p_endpoint_mtx, IPL_NET);
	bzero(&peer->p_endpoint, sizeof(peer->p_endpoint));

	task_set(&peer->p_send_initiation,
	    (void (*)(void *))wg_send_initiation, peer);
	task_set(&peer->p_clear_secrets,
	    (void (*)(void *))noise_remote_clear, &peer->p_remote);
	task_set(&peer->p_deliver_out, (void (*)(void *))wg_deliver_out, peer);
	task_set(&peer->p_deliver_in, (void (*)(void *))wg_deliver_in, peer);

	mq_init(&peer->p_stage_queue, MAX_STAGED_PKT, IPL_NET);
	mtx_init(&peer->p_encap_queue.q_mtx, IPL_NET);
	ml_init(&peer->p_encap_queue.q_list);
	mtx_init(&peer->p_decap_queue.q_mtx, IPL_NET);
	ml_init(&peer->p_decap_queue.q_list);

	SLIST_INIT(&peer->p_unused_index);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[0],
	    i_unused_entry);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[1],
	    i_unused_entry);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[2],
	    i_unused_entry);

	SLIST_INIT(&peer->p_aip);

	peer->p_start_onlist = 0;

	idx = SipHash24(&sc->sc_secret, public, WG_KEY_SIZE);
	idx &= sc->sc_peer_mask;

	rw_enter_write(&sc->sc_peer_lock);
	LIST_INSERT_HEAD(&sc->sc_peer[idx], peer, p_entry);
	sc->sc_peer_num++;
	rw_exit_write(&sc->sc_peer_lock);

	DPRINTF(sc, "Peer %llu created\n", peer->p_id);
	return peer;
}

struct wg_peer *
wg_peer_lookup(struct wg_softc *sc, const uint8_t public[WG_KEY_SIZE])
{
	uint8_t		 peer_key[WG_KEY_SIZE];
	struct wg_peer	*peer;
	uint64_t	 idx;

	idx = SipHash24(&sc->sc_secret, public, WG_KEY_SIZE);
	idx &= sc->sc_peer_mask;

	rw_enter_read(&sc->sc_peer_lock);
	LIST_FOREACH(peer, &sc->sc_peer[idx], p_entry) {
		noise_remote_keys(&peer->p_remote, peer_key, NULL);
		if (timingsafe_bcmp(peer_key, public, WG_KEY_SIZE) == 0)
			goto done;
	}
	peer = NULL;
done:
	rw_exit_read(&sc->sc_peer_lock);
	return peer;
}

void
wg_peer_destroy(struct wg_peer *peer)
{
	struct wg_softc	*sc = peer->p_sc;
	struct wg_aip *aip, *taip;

	rw_assert_wrlock(&sc->sc_lock);

	/* Remove peer from the pubkey hashtable and disable all timeouts.
	 * After this, and flushing wg_handshake_taskq, then no more handshakes
	 * can be started. */
	rw_enter_write(&sc->sc_peer_lock);
	LIST_REMOVE(peer, p_entry);
	sc->sc_peer_num--;
	rw_exit_write(&sc->sc_peer_lock);

	wg_timers_disable(&peer->p_timers);

	taskq_barrier(wg_handshake_taskq);

	/* Now we drop all allowed ips, to drop all outgoing packets to the
	 * peer. Then drop all the indexes to drop all incoming packets to the
	 * peer. Then we can flush if_snd, wg_crypt_taskq and then nettq to
	 * ensure no more references to the peer exist. */
	SLIST_FOREACH_SAFE(aip, &peer->p_aip, a_entry, taip)
		wg_aip_remove(sc, peer, &aip->a_data);

	noise_remote_clear(&peer->p_remote);

	NET_LOCK();
	while (!ifq_empty(&sc->sc_if.if_snd)) {
		NET_UNLOCK();
		tsleep_nsec(sc, PWAIT, "wg_ifq", 1000);
		NET_LOCK();
	}
	NET_UNLOCK();

	taskq_barrier(wg_crypt_taskq);
	taskq_barrier(net_tq(sc->sc_if.if_index));

	DPRINTF(sc, "Peer %llu destroyed\n", peer->p_id);
	explicit_bzero(peer, sizeof(*peer));
	pool_put(&wg_peer_pool, peer);
}

void
wg_peer_set_endpoint_from_tag(struct wg_peer *peer, struct wg_tag *t)
{
	if (memcmp(&t->t_endpoint, &peer->p_endpoint,
	    sizeof(t->t_endpoint)) == 0)
		return;

	mtx_enter(&peer->p_endpoint_mtx);
	peer->p_endpoint = t->t_endpoint;
	mtx_leave(&peer->p_endpoint_mtx);
}

void
wg_peer_set_sockaddr(struct wg_peer *peer, struct sockaddr *remote)
{
	mtx_enter(&peer->p_endpoint_mtx);
	memcpy(&peer->p_endpoint.e_remote, remote,
	       sizeof(peer->p_endpoint.e_remote));
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	mtx_leave(&peer->p_endpoint_mtx);
}

int
wg_peer_get_sockaddr(struct wg_peer *peer, struct sockaddr *remote)
{
	int	ret = 0;

	mtx_enter(&peer->p_endpoint_mtx);
	if (peer->p_endpoint.e_remote.r_sa.sa_family != AF_UNSPEC)
		memcpy(remote, &peer->p_endpoint.e_remote,
		       sizeof(peer->p_endpoint.e_remote));
	else
		ret = ENOENT;
	mtx_leave(&peer->p_endpoint_mtx);
	return ret;
}

void
wg_peer_clear_src(struct wg_peer *peer)
{
	mtx_enter(&peer->p_endpoint_mtx);
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	mtx_leave(&peer->p_endpoint_mtx);
}

void
wg_peer_get_endpoint(struct wg_peer *peer, struct wg_endpoint *endpoint)
{
	mtx_enter(&peer->p_endpoint_mtx);
	memcpy(endpoint, &peer->p_endpoint, sizeof(*endpoint));
	mtx_leave(&peer->p_endpoint_mtx);
}

void
wg_peer_counters_add(struct wg_peer *peer, uint64_t tx, uint64_t rx)
{
	mtx_enter(&peer->p_counters_mtx);
	peer->p_counters_tx += tx;
	peer->p_counters_rx += rx;
	mtx_leave(&peer->p_counters_mtx);
}

int
wg_aip_add(struct wg_softc *sc, struct wg_peer *peer, struct wg_aip_data *d)
{
	struct art_root	*root;
	struct art_node	*node;
	struct wg_aip	*aip;
	int		 ret = 0;

	switch (d->d_af) {
	case AF_INET:	root = sc->sc_aip4; break;
	case AF_INET6:	root = sc->sc_aip6; break;
	default: return EAFNOSUPPORT;
	}

	if ((aip = pool_get(&wg_aip_pool, PR_NOWAIT)) == NULL)
		return ENOBUFS;
	bzero(aip, sizeof(*aip));

	rw_enter_write(&root->ar_lock);
	node = art_insert(root, &aip->a_node, &d->d_addr, d->d_cidr);

	if (node == &aip->a_node) {
		aip->a_peer = peer;
		aip->a_data = *d;
		SLIST_INSERT_HEAD(&peer->p_aip, aip, a_entry);
		sc->sc_aip_num++;
	} else {
		pool_put(&wg_aip_pool, aip);
		if (((struct wg_aip *) node)->a_peer != peer)
			ret = EEXIST;
	}
	rw_exit_write(&root->ar_lock);
	return ret;
}

struct wg_peer *
wg_aip_lookup(struct art_root *root, void *addr)
{
	struct srp_ref	 sr;
	struct art_node	*node;

	node = art_match(root, addr, &sr);
	srp_leave(&sr);

	return node == NULL ? NULL : ((struct wg_aip *) node)->a_peer;
}

int
wg_aip_remove(struct wg_softc *sc, struct wg_peer *peer, struct wg_aip_data *d)
{
	struct srp_ref	 sr;
	struct art_root	*root;
	struct art_node	*node;
	struct wg_aip	*aip;
	int		 ret = 0;

	switch (d->d_af) {
	case AF_INET:	root = sc->sc_aip4; break;
	case AF_INET6:	root = sc->sc_aip6; break;
	default: return EAFNOSUPPORT;
	}

	rw_enter_write(&root->ar_lock);
	if ((node = art_lookup(root, &d->d_addr, d->d_cidr, &sr)) == NULL) {
		ret = ENOENT;
	} else if (((struct wg_aip *) node)->a_peer != peer) {
		ret = EXDEV;
	} else {
		aip = (struct wg_aip *)node;
		if (art_delete(root, node, &d->d_addr, d->d_cidr) == NULL)
			panic("art_delete failed to delete node %p", node);

		sc->sc_aip_num--;
		SLIST_REMOVE(&peer->p_aip, aip, wg_aip, a_entry);
		pool_put(&wg_aip_pool, aip);
	}

	srp_leave(&sr);
	rw_exit_write(&root->ar_lock);
	return ret;
}

int
wg_bind(struct wg_softc *sc)
{
	struct mbuf		 hostnam, rtable;
	struct socket		*so4, *so6;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	int			 ret, s;

	rw_enter_write(&sc->sc_so_lock);

	if ((ret = socreate(AF_INET, &so4, SOCK_DGRAM, 0)) != 0)
		goto error;
	if ((ret = socreate(AF_INET6, &so6, SOCK_DGRAM, 0)) != 0)
		goto error;

	m_inithdr(&hostnam);
	m_inithdr(&rtable);

	bzero(mtod(&rtable, u_int *), sizeof(u_int));
	*mtod(&rtable, u_int *) = sc->sc_udp_rtable;
	rtable.m_len = sizeof(u_int);

	/* Listen v4 */
	sin = mtod(&hostnam, struct sockaddr_in *);
	bzero(sin, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_port = sc->sc_udp_port;
	sin->sin_addr.s_addr = INADDR_ANY;
	hostnam.m_len = sin->sin_len;

	s = solock(so4);
	sotoinpcb(so4)->inp_upcall = wg_input;
	sotoinpcb(so4)->inp_upcall_arg = sc;

	if ((ret = sosetopt(so4, SOL_SOCKET, SO_RTABLE, &rtable)) != 0) {
		sounlock(so4, s);
		goto error;
	}

	if ((ret = sobind(so4, &hostnam, curproc)) != 0) {
		sounlock(so4, s);
		goto error;
	}

	/* Update port to whatever v4 chose */
	sc->sc_udp_port = sotoinpcb(so4)->inp_lport;
	sounlock(so4, s);

	/* Listen v6 */
	sin6 = mtod(&hostnam, struct sockaddr_in6 *);
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sc->sc_udp_port;
	sin6->sin6_addr = (struct in6_addr) { .s6_addr = { 0 } };
	hostnam.m_len = sin6->sin6_len;

	s = solock(so6);
	sotoinpcb(so6)->inp_upcall = wg_input;
	sotoinpcb(so6)->inp_upcall_arg = sc;

	if ((ret = sosetopt(so6, SOL_SOCKET, SO_RTABLE, &rtable)) != 0) {
		sounlock(so6, s);
		goto error;
	}

	if ((ret = sobind(so6, &hostnam, curproc)) != 0) {
		sounlock(so6, s);
		goto error;
	}
	sounlock(so6, s);

	/* Set wg_softc sockets to new values */
	sc->sc_so4 = so4;
	sc->sc_so6 = so6;

	rw_exit_write(&sc->sc_so_lock);
	return 0;
error:
	rw_exit_write(&sc->sc_so_lock);
	wg_unbind(sc);
	return ret;
}

void
wg_unbind(struct wg_softc *sc)
{
	struct socket	*so4;
	struct socket	*so6;

	rw_enter_write(&sc->sc_so_lock);
	so4 = sc->sc_so4;
	so6 = sc->sc_so6;
	sc->sc_so4 = NULL;
	sc->sc_so6 = NULL;

	if (so4 != NULL && soclose(so4, 0) != 0)
		panic("Unable to close wg socket");
	if (so6 != NULL && soclose(so6, 0) != 0)
		panic("Unable to close wg socket");
	rw_exit_write(&sc->sc_so_lock);
}

int
wg_send(struct wg_softc *sc, struct wg_endpoint *e, struct mbuf *m)
{
	struct mbuf	 peernam, *control = NULL;
	int		 ret;

	/* Get local control address before locking */
	if (e->e_remote.r_sa.sa_family == AF_INET) {
		if (e->e_local.l_in.s_addr != INADDR_ANY)
			control = sbcreatecontrol(&e->e_local.l_in,
			    sizeof(struct in_addr), IP_SENDSRCADDR,
			    IPPROTO_IP);
	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&e->e_local.l_in6))
			control = sbcreatecontrol(&e->e_local.l_pktinfo6,
			    sizeof(struct in6_pktinfo), IPV6_PKTINFO,
			    IPPROTO_IPV6);
	} else {
		return EAFNOSUPPORT;
	}

	/* Get remote address */
	peernam.m_type = MT_SONAME;
	peernam.m_next = NULL;
	peernam.m_nextpkt = NULL;
	peernam.m_data = (void *)&e->e_remote.r_sa;
	peernam.m_len = e->e_remote.r_sa.sa_len;
	peernam.m_flags = 0;

	rw_enter_read(&sc->sc_so_lock);
	if (e->e_remote.r_sa.sa_family == AF_INET && sc->sc_so4 != NULL)
		ret = sosend(sc->sc_so4, &peernam, NULL, m, control, 0);
	else if (e->e_remote.r_sa.sa_family == AF_INET6 && sc->sc_so6 != NULL)
		ret = sosend(sc->sc_so6, &peernam, NULL, m, control, 0);
	else {
		ret = ENOTCONN;
		m_freem(control);
		m_freem(m);
	}
	rw_exit_read(&sc->sc_so_lock);

	return ret;
}

int
wg_send_buf(struct wg_softc *sc, struct wg_endpoint *e, uint8_t *buf,
    size_t len)
{
	struct mbuf	*m;
	int		 ret = 0;

retry:
	m = m_gethdr(M_WAIT, MT_DATA);
	m->m_len = 0;
	m_copyback(m, 0, len, buf, M_WAIT);

	/* As we're sending a handshake packet here, we want high priority */
	m->m_pkthdr.pf.prio = IFQ_MAXPRIO;

	if (ret == 0) {
		ret = wg_send(sc, e, m);
		/* Retry if we couldn't bind to e->e_local */
		if (ret == EADDRNOTAVAIL) {
			bzero(&e->e_local, sizeof(e->e_local));
			goto retry;
		}
	} else {
		ret = wg_send(sc, e, m);
	}
	return ret;
}

struct wg_tag *
wg_tag_get(struct mbuf *m)
{
	struct m_tag	*mtag;

	if ((mtag = m_tag_find(m, PACKET_TAG_WG, NULL)) == NULL) {
		mtag = m_tag_get(PACKET_TAG_WG, sizeof(struct wg_tag),
		    M_NOWAIT);
		if (mtag == NULL)
			return (NULL);
		bzero(mtag + 1, sizeof(struct wg_tag));
		m_tag_prepend(m, mtag);
	}
	return ((struct wg_tag *)(mtag + 1));
}

/* The following section handles the timeout callbacks for a WireGuard session.
 * These functions provide an "event based" model for controling wg(8) session
 * timers. All function calls occur after the specified event below.
 *
 * wg_timers_event_data_sent:
 *	tx: data
 * wg_timers_event_data_received:
 *	rx: data
 * wg_timers_event_any_authenticated_packet_sent:
 *	tx: keepalive, data, handshake
 * wg_timers_event_any_authenticated_packet_received:
 *	rx: keepalive, data, handshake
 * wg_timers_event_any_authenticated_packet_traversal:
 *	tx, rx: keepalive, data, handshake
 * wg_timers_event_handshake_initiated:
 *	tx: initiation
 * wg_timers_event_handshake_responded:
 *	tx: response
 * wg_timers_event_handshake_complete:
 *	rx: response, confirmation data
 * wg_timers_event_session_derived:
 *	tx: response, rx: response
 * wg_timers_event_want_initiation:
 *	tx: data failed, old keys expiring
 *
 * The callback functions for t are:
 *
 * f_send_initiation
 *	will send an initiation to the peer associated to t
 * f_send_keepalive
 *	will send keepalive packet to peer, or staged packets instead
 * f_clear_staged
 *	clear staged packets for peer associated to t
 * f_clear_secrets
 *	clear all the sensitive ephemeral information
 * f_clear_src
 *	clear the source address of the peer
 */
void
wg_timers_init(struct wg_timers *t, struct wg_timers_fn *t_fn)
{
	bzero(t, sizeof(*t));
	rw_init(&t->t_lock, "wg_timers");
	mtx_init(&t->t_handshake_mtx, IPL_NET);

	t->t_fn = t_fn;

	timeout_set(&t->t_new_handshake,
	    (void (*)(void *))wg_timers_run_new_handshake, t);
	timeout_set(&t->t_send_keepalive,
	    (void (*)(void *))wg_timers_run_send_keepalive, t);
	timeout_set(&t->t_retry_handshake,
	    (void (*)(void *))wg_timers_run_retry_handshake, t);
	timeout_set(&t->t_persistent_keepalive,
	    (void (*)(void *))wg_timers_run_persistent_keepalive, t);
	timeout_set(&t->t_zero_key_material,
	    (void (*)(void *))wg_timers_run_zero_key_material, t);
}

void
wg_timers_enable(struct wg_timers *t)
{
	rw_enter_write(&t->t_lock);
	t->t_disabled = 0;
	rw_exit_write(&t->t_lock);
	wg_timers_run_persistent_keepalive(t);
}

void
wg_timers_disable(struct wg_timers *t)
{
	rw_enter_write(&t->t_lock);
	t->t_disabled = 1;
	t->t_need_another_keepalive = 0;
	rw_exit_write(&t->t_lock);

	timeout_del_barrier(&t->t_new_handshake);
	timeout_del_barrier(&t->t_send_keepalive);
	timeout_del_barrier(&t->t_retry_handshake);
	timeout_del_barrier(&t->t_persistent_keepalive);
	timeout_del_barrier(&t->t_zero_key_material);
}

void
wg_timers_set_persistent_keepalive(struct wg_timers *t, uint16_t interval)
{
	rw_enter_read(&t->t_lock);
	if (!t->t_disabled) {
		t->t_persistent_keepalive_interval = interval;
		wg_timers_run_persistent_keepalive(t);
	}
	rw_exit_read(&t->t_lock);
}

int
wg_timers_get_persistent_keepalive(struct wg_timers *t, uint16_t *interval)
{
	*interval = t->t_persistent_keepalive_interval;
	return *interval > 0 ? 0 : ENOENT;
}

void
wg_timers_get_last_handshake(struct wg_timers *t, struct timespec *time)
{
	mtx_enter(&t->t_handshake_mtx);
	*time = t->t_handshake_complete;
	mtx_leave(&t->t_handshake_mtx);
}

void
wg_timers_event_data_sent(struct wg_timers *t)
{
	int	msecs = NEW_HANDSHAKE_TIMEOUT * 1000;
	msecs += arc4random_uniform(REKEY_TIMEOUT_JITTER);

	rw_enter_read(&t->t_lock);
	if (!t->t_disabled && !timeout_pending(&t->t_new_handshake))
		timeout_add_msec(&t->t_new_handshake, msecs);
	rw_exit_read(&t->t_lock);
}

void
wg_timers_event_data_received(struct wg_timers *t)
{
	rw_enter_read(&t->t_lock);
	if (!t->t_disabled) {
		if (!timeout_pending(&t->t_send_keepalive))
			timeout_add_sec(&t->t_send_keepalive,
			    KEEPALIVE_TIMEOUT);
		else
			t->t_need_another_keepalive = 1;
	}
	rw_exit_read(&t->t_lock);
}

void
wg_timers_event_any_authenticated_packet_sent(struct wg_timers *t)
{
	timeout_del(&t->t_send_keepalive);
}

void
wg_timers_event_any_authenticated_packet_received(struct wg_timers *t)
{
	timeout_del(&t->t_new_handshake);
}

void
wg_timers_event_any_authenticated_packet_traversal(struct wg_timers *t)
{
	rw_enter_read(&t->t_lock);
	if (!t->t_disabled && t->t_persistent_keepalive_interval > 0)
		timeout_add_sec(&t->t_persistent_keepalive,
		    t->t_persistent_keepalive_interval);
	rw_exit_read(&t->t_lock);
}

void
wg_timers_event_handshake_initiated(struct wg_timers *t)
{
	int	msecs = REKEY_TIMEOUT * 1000;
	msecs += arc4random_uniform(REKEY_TIMEOUT_JITTER);

	rw_enter_read(&t->t_lock);
	if (!t->t_disabled)
		timeout_add_msec(&t->t_retry_handshake, msecs);
	rw_exit_read(&t->t_lock);
}

void
wg_timers_event_handshake_responded(struct wg_timers *t)
{
	mtx_enter(&t->t_handshake_mtx);
	getmicrouptime(&t->t_handshake_touch);
	mtx_leave(&t->t_handshake_mtx);
}

void
wg_timers_event_handshake_complete(struct wg_timers *t)
{
	int	ready = 0;

	rw_enter_read(&t->t_lock);
	if (!t->t_disabled) {
		mtx_enter(&t->t_handshake_mtx);
		t->t_handshake_retries = 0;
		timeout_del(&t->t_retry_handshake);
		getnanotime(&t->t_handshake_complete);
		mtx_leave(&t->t_handshake_mtx);
		ready = 1;
	}

	if (ready)
		t->t_fn->f_send_keepalive(t);
	rw_exit_read(&t->t_lock);
}

void
wg_timers_event_session_derived(struct wg_timers *t)
{
	rw_enter_read(&t->t_lock);
	if (!t->t_disabled)
		timeout_add_sec(&t->t_zero_key_material, REJECT_AFTER_TIME * 3);
	rw_exit_read(&t->t_lock);
}

void
wg_timers_event_want_initiation(struct wg_timers *t)
{
	int	ready = 0;

	rw_enter_read(&t->t_lock);
	mtx_enter(&t->t_handshake_mtx);
	if (!t->t_disabled && ratecheck(&t->t_handshake_touch,
	    &rekey_interval)) {
		t->t_handshake_retries = 0;
		ready = 1;
	}
	mtx_leave(&t->t_handshake_mtx);

	if (ready)
		t->t_fn->f_send_initiation(t, 0, 0);
	rw_exit_read(&t->t_lock);
}

void
wg_timers_run_new_handshake(struct wg_timers *t)
{
	int	ready = 0;

	mtx_enter(&t->t_handshake_mtx);
	if (ratecheck(&t->t_handshake_touch, &rekey_interval)) {
		t->t_handshake_retries = 0;
		ready = 1;
	}
	mtx_leave(&t->t_handshake_mtx);

	if (ready) {
		t->t_fn->f_clear_src(t);
		t->t_fn->f_clear_secrets(t);
		t->t_fn->f_send_initiation(t, 0, NEW_HANDSHAKE_TIMEOUT);
	}
}

void
wg_timers_run_send_keepalive(struct wg_timers *t)
{
	t->t_fn->f_send_keepalive(t);
	if (t->t_need_another_keepalive) {
		t->t_need_another_keepalive = 0;
		timeout_add_sec(&t->t_send_keepalive, KEEPALIVE_TIMEOUT);
	}
}

void
wg_timers_run_retry_handshake(struct wg_timers *t)
{
	int	retries, ready = 0;

	mtx_enter(&t->t_handshake_mtx);
	if (ratecheck(&t->t_handshake_touch, &rekey_interval)) {
		retries = ++t->t_handshake_retries;
		ready = 1;
	}
	mtx_leave(&t->t_handshake_mtx);

	if (!ready)
		return;

	if (retries < MAX_TIMER_HANDSHAKES) {
		t->t_fn->f_clear_src(t);
		t->t_fn->f_send_initiation(t, retries, REKEY_TIMEOUT);
	} else {
		t->t_fn->f_send_initiation(t, retries, -1);
		timeout_del(&t->t_send_keepalive);
		t->t_fn->f_clear_staged(t);
		if (!timeout_pending(&t->t_zero_key_material))
			timeout_add_sec(&t->t_zero_key_material,
			    REJECT_AFTER_TIME * 3);
	}
}

void
wg_timers_run_zero_key_material(struct wg_timers *t)
{
	t->t_fn->f_clear_secrets(t);
}

void
wg_timers_run_persistent_keepalive(struct wg_timers *t)
{
	if (t->t_persistent_keepalive_interval != 0)
		t->t_fn->f_send_keepalive(t);
}

/* The following wrapper functions glue wg_timers and wg_peer */
void
wg_timers_peer_send_initiation(struct wg_timers *t, int retries, int timeout)
{
	struct wg_peer *peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	if (timeout == -1) {
		DPRINTF(peer->p_sc, "Handshake for peer %llu did not complete "
		    "after %d retries, giving up\n", peer->p_id, retries);
		return;
	} else if (retries == 0 && timeout == 0) {
		DPRINTF(peer->p_sc, "Sending handshake initiation to peer "
		    "%llu\n", peer->p_id);
	} else if (retries == 0 && timeout != 0) {
		DPRINTF(peer->p_sc, "Retrying handshake with peer %llu "
		    "because we stopped hearing back after %d seconds\n",
		    peer->p_id, timeout);
	} else {
		DPRINTF(peer->p_sc, "Handshake for peer %llu did not complete "
		    "after %d seconds, retrying (try %d)\n", peer->p_id,
		    timeout, retries);
	}
	task_add(wg_handshake_taskq, &peer->p_send_initiation);
}

void
wg_timers_peer_send_keepalive(struct wg_timers *_t)
{
	struct wg_peer *peer = CONTAINER_OF(_t, struct wg_peer, p_timers);
	struct wg_softc	*sc = peer->p_sc;
	struct wg_tag	*t;
	struct mbuf	*m;

	if (!mq_empty(&peer->p_stage_queue))
		goto send;

	if ((m = m_gethdr(M_NOWAIT, MT_DATA)) == NULL)
		return;

	if ((t = wg_tag_get(m)) == NULL) {
		m_freem(m);
		return;
	}

	m->m_len = 0;
	m_calchdrlen(m);

	t->t_peer = peer;
	t->t_mbuf = NULL;
	t->t_done = 0;

	if (mq_push(&peer->p_stage_queue, m) != 0)
		counters_inc(sc->sc_if.if_counters, ifc_oqdrops);
send:
	if (noise_remote_ready(&peer->p_remote) == 0) {
		wg_queue_out(sc, peer);
		task_add(wg_crypt_taskq, &sc->sc_encap);
	} else {
		wg_timers_event_want_initiation(&peer->p_timers);
	}
}

void
wg_timers_peer_clear_secrets(struct wg_timers *t)
{
	struct wg_peer *peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	DPRINTF(peer->p_sc, "Zeroing out keys for peer %llu\n", peer->p_id);
	task_add(wg_handshake_taskq, &peer->p_clear_secrets);
}

void
wg_timers_peer_clear_staged(struct wg_timers *t)
{
	struct wg_peer *peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	mq_purge(&peer->p_stage_queue);
}

void
wg_timers_peer_clear_src(struct wg_timers *t)
{
	struct wg_peer *peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	wg_peer_clear_src(peer);
}


/* The following functions handle handshakes */
int
wg_peer_send_buf(struct wg_peer *peer, uint8_t *buf, size_t len)
{
	struct wg_endpoint	 endpoint;

	wg_peer_counters_add(peer, len, 0);
	wg_timers_event_any_authenticated_packet_traversal(&peer->p_timers);
	wg_timers_event_any_authenticated_packet_sent(&peer->p_timers);
	wg_peer_get_endpoint(peer, &endpoint);
	return wg_send_buf(peer->p_sc, &endpoint, buf, len);
}

int
wg_send_initiation(struct wg_peer *peer)
{
	struct wg_pkt_initiation pkt;
	int ret;

	if ((ret = noise_create_initiation(&peer->p_remote, &pkt.init)) != 0)
		return ret;

	pkt.t = WG_PKT_INITIATION;
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt)-sizeof(pkt.m));

	ret = wg_peer_send_buf(peer, (uint8_t *)&pkt, sizeof(pkt));
	if (ret == 0)
		wg_timers_event_handshake_initiated(&peer->p_timers);
	return ret;
}

int
wg_send_response(struct wg_peer *peer)
{
	struct wg_pkt_response	 pkt;
	int ret;

	if ((ret = noise_create_response(&peer->p_remote, &pkt.resp)) != 0)
		return ret;

	DPRINTF(peer->p_sc, "Sending handshake response to peer %llu\n",
	    peer->p_id);

	pkt.t = WG_PKT_RESPONSE;
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt)-sizeof(pkt.m));

	ret = wg_peer_send_buf(peer, (uint8_t *)&pkt, sizeof(pkt));
	if (ret == 0)
		wg_timers_event_handshake_responded(&peer->p_timers);
	return ret;
}

int
wg_send_cookie(struct wg_softc *sc, struct cookie_macs *cm, uint32_t idx,
    struct wg_endpoint *e)
{
	struct wg_pkt_cookie	pkt;

	DPRINTF(sc, "Sending cookie response for denied handshake message\n");

	pkt.t = WG_PKT_COOKIE;
	pkt.r_idx = idx;

	cookie_checker_create_payload(&sc->sc_cookie, cm, pkt.nonce,
	    pkt.ec, &e->e_remote.r_sa);

	return wg_send_buf(sc, e, (uint8_t *)&pkt, sizeof(pkt));
}

void
wg_handshake(struct wg_softc *sc, struct mbuf *m)
{
	struct wg_tag			*t;
	struct wg_pkt_initiation	*init;
	struct wg_pkt_response		*resp;
	struct wg_pkt_cookie		*cook;
	struct wg_peer			*peer;
	struct noise_remote		*remote;
	int				 res, underload = 0;
	static struct timeval		 wg_last_underload; /* microuptime */

	if (mq_len(&sc->sc_handshake_queue) >= MAX_QUEUED_HANDSHAKES/8) {
		getmicrouptime(&wg_last_underload);
		underload = 1;
	} else if (wg_last_underload.tv_sec != 0) {
		if (!ratecheck(&wg_last_underload, &underload_interval))
			underload = 1;
		else
			bzero(&wg_last_underload, sizeof(wg_last_underload));
	}

	t = wg_tag_get(m);

	switch (*mtod(m, uint32_t *)) {
	case WG_PKT_INITIATION:
		init = mtod(m, struct wg_pkt_initiation *);

		res = cookie_checker_validate_macs(&sc->sc_cookie, &init->m,
				init, sizeof(*init) - sizeof(init->m),
				underload, &t->t_endpoint.e_remote.r_sa);

		if (res == EINVAL) {
			DPRINTF(sc, "Invalid initiation MAC\n");
			goto error;
		} else if (res == ECONNREFUSED) {
			DPRINTF(sc, "Handshake ratelimited\n");
			goto error;
		} else if (res == EAGAIN) {
			wg_send_cookie(sc, &init->m, init->init.s_idx,
			    &t->t_endpoint);
			goto error;
		} else if (res != 0) {
			panic("unexpected response: %d\n", res);
		}

		if (noise_consume_initiation(&sc->sc_local, &remote,
		    &init->init) != 0) {
			DPRINTF(sc, "Invalid handshake initiation\n");
			goto error;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);

		DPRINTF(sc, "Receiving handshake initiation from peer %llu\n",
				peer->p_id);

		wg_peer_counters_add(peer, 0, sizeof(*init));
		wg_peer_set_endpoint_from_tag(peer, t);
		res = wg_send_response(peer);
		if (res == 0 && noise_remote_promote(&peer->p_remote) == 0) {
			wg_timers_event_session_derived(&peer->p_timers);
		}
		break;
	case WG_PKT_RESPONSE:
		resp = mtod(m, struct wg_pkt_response *);

		res = cookie_checker_validate_macs(&sc->sc_cookie, &resp->m,
				resp, sizeof(*resp) - sizeof(resp->m),
				underload, &t->t_endpoint.e_remote.r_sa);

		if (res == EINVAL) {
			DPRINTF(sc, "Invalid initiation MAC\n");
			goto error;
		} else if (res == ECONNREFUSED) {
			DPRINTF(sc, "Handshake ratelimited\n");
			goto error;
		} else if (res == EAGAIN) {
			wg_send_cookie(sc, &init->m, init->init.s_idx,
			    &t->t_endpoint);
			goto error;
		} else if (res != 0) {
			panic("unexpected response: %d\n", res);
		}

		if ((remote = wg_index_get(sc, resp->resp.r_idx)) == NULL) {
			DPRINTF(sc, "Unknown handshake response\n");
			goto error;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);

		if (noise_consume_response(remote, &resp->resp) != 0) {
			DPRINTF(sc, "Invalid handshake response\n");
			goto error;
		}

		DPRINTF(sc, "Receiving handshake response from peer %llu\n",
				peer->p_id);

		wg_peer_counters_add(peer, 0, sizeof(*resp));
		wg_peer_set_endpoint_from_tag(peer, t);
		if (noise_remote_promote(&peer->p_remote) == 0) {
			wg_timers_event_session_derived(&peer->p_timers);
			wg_timers_event_handshake_complete(&peer->p_timers);
		}
		break;
	case WG_PKT_COOKIE:
		cook = mtod(m, struct wg_pkt_cookie *);

		if ((remote = wg_index_get(sc, cook->r_idx)) == NULL) {
			DPRINTF(sc, "Unknown cookie index\n");
			goto error;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);

		if (cookie_maker_consume_payload(&peer->p_cookie,
		    cook->nonce, cook->ec) != 0) {
			DPRINTF(sc, "Could not decrypt cookie response\n");
			goto error;
		}

		DPRINTF(sc, "Receiving cookie response\n");
		goto error;
	default:
		panic("invalid packet in handshake queue");
	}

	wg_timers_event_any_authenticated_packet_received(&peer->p_timers);
	wg_timers_event_any_authenticated_packet_traversal(&peer->p_timers);
error:
	m_freem(m);
}

void
wg_handshake_worker(struct wg_softc *sc)
{
	struct mbuf *m;
	while ((m = mq_dequeue(&sc->sc_handshake_queue)) != NULL)
		wg_handshake(sc, m);
}

/* The following functions handle encapsulation (encryption) and
 * decapsulation (decryption). The wg_{en,de}cap functions will run in the
 * sc_crypt_taskq, while wg_deliver_{in,out} must be serialised and will run
 * in nettq.
 *
 * The packets are tracked in two queues, a serial queue and a parallel queue.
 *  - The parallel queue is used to distribute the encryption across multiple
 *    threads.
 *  - The serial queue ensures that packets are not reordered and are
 *    delievered in sequence.
 * The wg_tag attached to the packet contains two flags to help the two queues
 * interact.
 *  - t_done: The parallel queue has finished with the packet, now the serial
 *            queue can do it's work.
 *  - t_mbuf: Used to store the *crypted packet. in the case of encryption,
 *            this is a newly allocated packet, and in the case of decryption,
 *            it is a pointer to the same packet, that has been decrypted and
 *            truncated. If t_mbuf is NULL, then *cryption failed and this
 *            packet should not be passed.
 * wg_{en,de}cap work on the parallel queue, while wg_deliver_{in,out} work
 * on the serial queue. */
void
wg_encap(struct wg_softc *sc, struct mbuf *m)
{
	int res = 0;
	struct wg_pkt_data	*data;
	struct wg_peer		*peer;
	struct wg_tag		*t;
	struct mbuf		*mc;
	size_t			 padding_len, plaintext_len, out_len;

	t = wg_tag_get(m);
	peer = t->t_peer;

	padding_len = WG_PKT_PADDING(m->m_pkthdr.len);
	plaintext_len = m->m_pkthdr.len + padding_len;
	out_len = sizeof(struct wg_pkt_data) + plaintext_len + NOISE_MAC_SIZE;

	/* For the time being we allocate a new packet with sufficient size to
	 * hold the encrypted data and headers. It would be difficult to
	 * overcome as p_encap_queue (mbuf_list) holds a reference to the mbuf.
	 * If we m_makespace or similar, we risk corrupting that list.
	 * Additionally, we only pass a buf and buf length to
	 * noise_remote_encrypt. Technically it would be possible to teach
	 * noise_remote_encrypt about mbufs, but we would need to sort out the
	 * p_encap_queue situation first. */
	if ((mc = m_clget(NULL, M_NOWAIT, out_len)) == NULL)
		goto error;

	data = mtod(mc, struct wg_pkt_data *);
	m_copydata(m, 0, m->m_pkthdr.len, data->data.buf);
	bzero(data->data.buf + m->m_pkthdr.len, padding_len);
	data->t = WG_PKT_DATA;

	res = noise_remote_encrypt(&peer->p_remote, &data->data, plaintext_len);

	if (res == 0) {
		/* Do nothing, check 0 to fasttrack most likey result */
	} else if (res == EINVAL) {
		wg_timers_event_want_initiation(&peer->p_timers);
		m_freem(mc);
		goto error;
	} else if (res == ESTALE) {
		wg_timers_event_want_initiation(&peer->p_timers);
	} else if (res != 0) {
		panic("unexpected result: %d\n", res);
	}

	/* A packet with length 0 is a keepalive packet */
	if (m->m_pkthdr.len == 0)
		DPRINTF(sc, "Sending keepalive packet to peer %llu\n",
		    peer->p_id);

	mc->m_pkthdr.ph_loopcnt = m->m_pkthdr.ph_loopcnt;
	mc->m_flags &= ~(M_MCAST | M_BCAST);
	mc->m_len = out_len;
	m_calchdrlen(mc);

	/* We would count ifc_opackets, ifc_obytes of m here, except if_snd
	 * already does that for us, so no need to worry about it.
	counters_pkt(sc->sc_if.if_counters, ifc_opackets, ifc_obytes,
	    m->m_pkthdr.len); */
	wg_peer_counters_add(peer, mc->m_pkthdr.len, 0);

	t->t_mbuf = mc;
error:
	t->t_done = 1;
	task_add(net_tq(sc->sc_if.if_index), &peer->p_deliver_out);
}

void
wg_decap(struct wg_softc *sc, struct mbuf *m)
{
	int			 res, len;
	struct ip		*ip;
	struct ip6_hdr		*ip6;
	struct wg_pkt_data	*data;
	struct wg_peer		*peer, *allowed_peer;
	struct wg_tag		*t;
	size_t			 payload_len;

	t = wg_tag_get(m);
	peer = t->t_peer;

	/* Likewise to wg_encap, we pass a buf and buf length to 
	 * noise_remote_decrypt. Again, possible to teach it about mbufs
	 * but need to get over the p_decap_queue situation first. However,
	 * we do not need to allocate a new mbuf as the decrypted packet is
	 * strictly smaller than encrypted. We just set t_mbuf to m and
	 * wg_deliver_in knows how to deal with that. */
	data = mtod(m, struct wg_pkt_data *);
	payload_len = m->m_pkthdr.len - sizeof(struct wg_pkt_data);
	res = noise_remote_decrypt(&peer->p_remote, &data->data, payload_len);

	if (res == 0) {
		/* Do nothing, check 0 to fasttrack most likey result */
	} else if (res == EINVAL) {
		goto error;
	} else if (res == ECONNRESET) {
		wg_timers_event_handshake_complete(&peer->p_timers);
	} else if (res == ESTALE) {
		wg_timers_event_want_initiation(&peer->p_timers);
	} else if (res != 0) {
		panic("unexpected response: %d\n", res);
	}

	wg_peer_set_endpoint_from_tag(peer, t);

	wg_peer_counters_add(peer, 0, m->m_pkthdr.len);

	m_adj(m, sizeof(struct wg_pkt_data));
	m_adj(m, -NOISE_MAC_SIZE);

	counters_pkt(sc->sc_if.if_counters, ifc_ipackets, ifc_ibytes,
	    m->m_pkthdr.len);

	/* A packet with length 0 is a keepalive packet */
	if (m->m_pkthdr.len == 0) {
		DPRINTF(sc, "Receiving keepalive packet from peer "
		    "%llu\n", peer->p_id);
		goto done;
	}

	/* We can let the network stack handle the intricate validation of the
	 * IP header, we just worry about the sizeof and the version, so we can
	 * read the source address in wg_aip_lookup.
	 *
	 * We also need to trim the packet, as it was likely paddded before
	 * encryption. While we could drop it here, it will be more helpful to
	 * pass it to bpf_mtap and use the counters that people are expecting
	 * in ipv4_input and ipv6_input. We can rely on ipv4_input and
	 * ipv6_input to properly validate the headers. */
	ip = mtod(m, struct ip *);
	ip6 = mtod(m, struct ip6_hdr *);

	if (m->m_pkthdr.len >= sizeof(struct ip) && ip->ip_v == IPVERSION) {
		m->m_pkthdr.ph_family = AF_INET;

		len = ntohs(ip->ip_len);
		if (len >= sizeof(struct ip) && len < m->m_pkthdr.len)
			m_adj(m, len - m->m_pkthdr.len);

		allowed_peer = wg_aip_lookup(sc->sc_aip4, &ip->ip_src);
	} else if (m->m_pkthdr.len >= sizeof(struct ip6_hdr) &&
	    (ip6->ip6_vfc & IPV6_VERSION_MASK) == IPV6_VERSION) {
		m->m_pkthdr.ph_family = AF_INET6;

		len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
		if (len < m->m_pkthdr.len)
			m_adj(m, len - m->m_pkthdr.len);

		allowed_peer = wg_aip_lookup(sc->sc_aip6, &ip6->ip6_src);
	} else {
		DPRINTF(sc, "Packet is neither ipv4 nor ipv6 from "
		    "peer %llu\n", peer->p_id);
		goto error;
	}

	if (peer != allowed_peer) {
		DPRINTF(sc, "Packet has unallowed src IP from peer "
		    "%llu\n", peer->p_id);
		goto error;
	}

	/* We can mark incoming packet csum OK. We mark all flags OK
	 * irrespective to the packet type. */
	m->m_pkthdr.csum_flags |= (M_IPV4_CSUM_IN_OK | M_TCP_CSUM_IN_OK |
	    M_UDP_CSUM_IN_OK | M_ICMP_CSUM_IN_OK);
	m->m_pkthdr.csum_flags &= ~(M_IPV4_CSUM_IN_BAD | M_TCP_CSUM_IN_BAD |
	    M_UDP_CSUM_IN_BAD | M_ICMP_CSUM_IN_BAD);

	m->m_pkthdr.ph_ifidx = sc->sc_if.if_index;
	m->m_pkthdr.ph_rtableid = sc->sc_if.if_rdomain;
	m->m_flags &= ~(M_MCAST | M_BCAST);
	pf_pkt_addr_changed(m);

done:
	t->t_mbuf = m;
error:
	t->t_done = 1;
	task_add(net_tq(sc->sc_if.if_index), &peer->p_deliver_in);
}

void
wg_encap_worker(struct wg_softc *sc)
{
	struct mbuf *m;
	while ((m = wg_ring_dequeue(&sc->sc_encap_ring)) != NULL)
		wg_encap(sc, m);
}

void
wg_decap_worker(struct wg_softc *sc)
{
	struct mbuf *m;
	while ((m = wg_ring_dequeue(&sc->sc_decap_ring)) != NULL)
		wg_decap(sc, m);
}

void
wg_deliver_out(struct wg_peer *peer)
{
	struct wg_endpoint	 endpoint;
	struct wg_tag		*t;
	struct mbuf		*m;
	struct wg_softc		*sc = peer->p_sc;
	int			 ret;

	wg_peer_get_endpoint(peer, &endpoint);

	while ((m = wg_queue_dequeue(&peer->p_encap_queue, &t)) != NULL) {
		/* t_mbuf will contain the encrypted packet */
		if (t->t_mbuf == NULL){
			counters_inc(sc->sc_if.if_counters, ifc_oerrors);
			m_freem(m);
			continue;
		}

		ret = wg_send(sc, &endpoint, t->t_mbuf);

		if (ret == 0) {
			wg_timers_event_any_authenticated_packet_traversal(
			    &peer->p_timers);
			wg_timers_event_any_authenticated_packet_sent(
			    &peer->p_timers);

			if (m->m_pkthdr.len != 0)
				wg_timers_event_data_sent(&peer->p_timers);
		} else if (ret == EADDRNOTAVAIL) {
			wg_peer_clear_src(peer);
			wg_peer_get_endpoint(peer, &endpoint);
		}

		m_freem(m);
	}
}

void
wg_deliver_in(struct wg_peer *peer)
{
	struct wg_tag	*t;
	struct mbuf	*m;
	struct wg_softc	*sc = peer->p_sc;

	while ((m = wg_queue_dequeue(&peer->p_decap_queue, &t)) != NULL) {
		/* t_mbuf will contain the decrypted packet */
		if (t->t_mbuf == NULL) {
			counters_inc(sc->sc_if.if_counters, ifc_ierrors);
			m_freem(m);
			continue;
		}

		/* From here on m == t->t_mbuf */
		KASSERT(m == t->t_mbuf);

		wg_timers_event_any_authenticated_packet_received(
		    &peer->p_timers);
		wg_timers_event_any_authenticated_packet_traversal(
		    &peer->p_timers);

		if (m->m_pkthdr.len == 0) {
			m_freem(m);
			continue;
		}

#if NBPFILTER > 0
		if (sc->sc_if.if_bpf != NULL)
			bpf_mtap_af(sc->sc_if.if_bpf,
			    m->m_pkthdr.ph_family, m, BPF_DIRECTION_IN);
#endif

		NET_LOCK();
		if (m->m_pkthdr.ph_family == AF_INET)
			ipv4_input(&sc->sc_if, m);
		else if (m->m_pkthdr.ph_family == AF_INET6)
			ipv6_input(&sc->sc_if, m);
		else
			panic("invalid ph_family");
		NET_UNLOCK();

		wg_timers_event_data_received(&peer->p_timers);
	}
}

/* ring */
int
wg_queue_in(struct wg_softc *sc, struct wg_peer *peer, struct mbuf *m)
{
	struct wg_ring		*parallel = &sc->sc_decap_ring;
	struct wg_queue		*serial = &peer->p_decap_queue;
	struct wg_tag		*t;

	mtx_enter(&serial->q_mtx);
	if (serial->q_list.ml_len < MAX_QUEUED_PKT) {
		ml_enqueue(&serial->q_list, m);
		mtx_leave(&serial->q_mtx);
	} else {
		mtx_leave(&serial->q_mtx);
		return ENOBUFS;
	}

	mtx_enter(&parallel->r_mtx);
	if (parallel->r_tail - parallel->r_head < MAX_QUEUED_PKT) {
		parallel->r_buf[parallel->r_tail & MAX_QUEUED_PKT_MASK] = m;
		parallel->r_tail++;
		mtx_leave(&parallel->r_mtx);
	} else {
		mtx_leave(&parallel->r_mtx);
		t = wg_tag_get(m);
		t->t_done = 1;
		return ENOBUFS;
	}

	return 0;
}

void
wg_queue_out(struct wg_softc *sc, struct wg_peer *peer)
{
	struct wg_ring		*parallel = &sc->sc_encap_ring;
	struct wg_queue		*serial = &peer->p_encap_queue;
	struct mbuf_list 	 ml, ml_free;
	struct mbuf		*m;
	struct wg_tag		*t;
	int			 dropped;

	/* We delist all staged packets and then add them to the queues. This
	 * can race with wg_start when called from wg_send_keepalive, however
	 * wg_start will not race as it is serialised. */
	mq_delist(&peer->p_stage_queue, &ml);
	ml_init(&ml_free);

	while ((m = ml_dequeue(&ml)) != NULL) {
		mtx_enter(&serial->q_mtx);
		if (serial->q_list.ml_len < MAX_QUEUED_PKT) {
			ml_enqueue(&serial->q_list, m);
			mtx_leave(&serial->q_mtx);
		} else {
			mtx_leave(&serial->q_mtx);
			ml_enqueue(&ml_free, m);
			continue;
		}

		mtx_enter(&parallel->r_mtx);
		if (parallel->r_tail - parallel->r_head < MAX_QUEUED_PKT) {
			parallel->r_buf[parallel->r_tail & MAX_QUEUED_PKT_MASK] = m;
			parallel->r_tail++;
			mtx_leave(&parallel->r_mtx);
		} else {
			mtx_leave(&parallel->r_mtx);
			t = wg_tag_get(m);
			t->t_done = 1;
		}
	}

	if ((dropped = ml_purge(&ml_free)) > 0)
		counters_add(sc->sc_if.if_counters, ifc_oqdrops, dropped);
}

struct mbuf *
wg_ring_dequeue(struct wg_ring *r)
{
	struct mbuf *m = NULL;
	mtx_enter(&r->r_mtx);
	if (r->r_head != r->r_tail) {
		m = r->r_buf[r->r_head & MAX_QUEUED_PKT_MASK];
		r->r_head++;
	}
	mtx_leave(&r->r_mtx);
	return m;
}

struct mbuf *
wg_queue_dequeue(struct wg_queue *q, struct wg_tag **t)
{
	struct mbuf *m;
	mtx_enter(&q->q_mtx);
	if ((m = q->q_list.ml_head) != NULL && (*t = wg_tag_get(m))->t_done)
		ml_dequeue(&q->q_list);
	else
		m = NULL;
	mtx_leave(&q->q_mtx);
	return m;
}

size_t
wg_queue_len(struct wg_queue *q)
{
	size_t len;
	mtx_enter(&q->q_mtx);
	len = q->q_list.ml_len;
	mtx_leave(&q->q_mtx);
	return len;
}

/* alloc */
struct noise_remote *
wg_remote_get(struct wg_softc *sc, uint8_t public[NOISE_KEY_SIZE])
{
	struct wg_peer *peer;
	if ((peer = wg_peer_lookup(sc, public)) == NULL)
		return NULL;
	return &peer->p_remote;
}

uint32_t
wg_index_set(struct wg_softc *sc, struct noise_remote *remote)
{
	struct wg_index *index, *iter;
	struct wg_peer	*peer;
	uint32_t	 key;

	/* We can modify this without a lock as wg_index_set, wg_index_drop are
	 * guaranteed to be serialised (per remote). */
	peer = CONTAINER_OF(remote, struct wg_peer, p_remote);
	index = SLIST_FIRST(&peer->p_unused_index);
	KASSERT(index != NULL);
	SLIST_REMOVE_HEAD(&peer->p_unused_index, i_unused_entry);

	index->i_value = remote;

	rw_enter_write(&sc->sc_index_lock);
assign_id:
	key = index->i_key = arc4random();
	key &= sc->sc_index_mask;
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == index->i_key)
			goto assign_id;

	LIST_INSERT_HEAD(&sc->sc_index[key], index, i_entry);

	rw_exit_write(&sc->sc_index_lock);

	/* Likewise, no need to lock for index here. */
	return index->i_key;
}

struct noise_remote *
wg_index_get(struct wg_softc *sc, uint32_t key0)
{
	struct wg_index		*iter;
	struct noise_remote	*remote = NULL;
	uint32_t		 key = key0 & sc->sc_index_mask;

	rw_enter_read(&sc->sc_index_lock);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			remote = iter->i_value;
			break;
		}
	rw_exit_read(&sc->sc_index_lock);
	return remote;
}

void
wg_index_drop(struct wg_softc *sc, uint32_t key0)
{
	struct wg_index	*iter;
	struct wg_peer	*peer = NULL;
	uint32_t	 key = key0 & sc->sc_index_mask;

	rw_enter_write(&sc->sc_index_lock);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			LIST_REMOVE(iter, i_entry);
			break;
		}
	rw_exit_write(&sc->sc_index_lock);

	/* We expect a peer */
	peer = CONTAINER_OF(iter->i_value, struct wg_peer, p_remote);
	KASSERT(peer != NULL);
	SLIST_INSERT_HEAD(&peer->p_unused_index, iter, i_unused_entry);
}

/* IO functions */
struct mbuf *
wg_input(void *_sc, struct mbuf *m, struct ip *ip, struct ip6_hdr *ip6,
    void *_uh, int hlen)
{
	struct wg_pkt_data	*data;
	struct noise_remote	*remote;
	struct wg_tag		*t;
	struct wg_softc		*sc = _sc;
	struct udphdr		*uh = _uh;

	NET_ASSERT_LOCKED();

	if ((t = wg_tag_get(m)) == NULL) {
		m_freem(m);
		return NULL;
	}

	if (ip != NULL) {
		t->t_endpoint.e_remote.r_sa.sa_len = sizeof(struct sockaddr_in);
		t->t_endpoint.e_remote.r_sa.sa_family = AF_INET;
		t->t_endpoint.e_remote.r_sin.sin_port = uh->uh_sport;
		t->t_endpoint.e_remote.r_sin.sin_addr = ip->ip_src;
		t->t_endpoint.e_local.l_in = ip->ip_dst;
	} else if (ip6 != NULL) {
		t->t_endpoint.e_remote.r_sa.sa_len = sizeof(struct sockaddr_in6);
		t->t_endpoint.e_remote.r_sa.sa_family = AF_INET6;
		t->t_endpoint.e_remote.r_sin6.sin6_port = uh->uh_sport;
		t->t_endpoint.e_remote.r_sin6.sin6_addr = ip6->ip6_src;
		t->t_endpoint.e_local.l_in6 = ip6->ip6_dst;
	} else {
		m_freem(m);
		return NULL;
	}

	/* m has a IP/IPv6 header of hlen length, we don't need it anymore. */
	m_adj(m, hlen);

	if (m_defrag(m, M_NOWAIT) != 0)
		return NULL;

	if ((m->m_pkthdr.len == sizeof(struct wg_pkt_initiation) &&
		*mtod(m, uint32_t *) == WG_PKT_INITIATION) ||
	    (m->m_pkthdr.len == sizeof(struct wg_pkt_response) &&
		*mtod(m, uint32_t *) == WG_PKT_RESPONSE) ||
	    (m->m_pkthdr.len == sizeof(struct wg_pkt_cookie) &&
		*mtod(m, uint32_t *) == WG_PKT_COOKIE)) {

		if (mq_enqueue(&sc->sc_handshake_queue, m) != 0)
			DPRINTF(sc, "Dropping handshake packet\n");
		task_add(wg_handshake_taskq, &sc->sc_handshake);

	} else if (m->m_pkthdr.len >= sizeof(struct wg_pkt_data) +
	    NOISE_MAC_SIZE && *mtod(m, uint32_t *) == WG_PKT_DATA) {

		data = mtod(m, struct wg_pkt_data *);

		if ((remote = wg_index_get(sc, data->data.r_idx)) != NULL) {
			t->t_peer = CONTAINER_OF(remote, struct wg_peer,
			    p_remote);
			t->t_mbuf = NULL;
			t->t_done = 0;

			if (wg_queue_in(sc, t->t_peer, m) != 0)
				counters_inc(sc->sc_if.if_counters,
				    ifc_iqdrops);
			task_add(wg_crypt_taskq, &sc->sc_decap);
		} else {
			counters_inc(sc->sc_if.if_counters, ifc_ierrors);
			m_freem(m);
		}
	} else {
		counters_inc(sc->sc_if.if_counters, ifc_ierrors);
		m_freem(m);
	}

	return NULL;
}

void
wg_start(struct ifnet *ifp)
{
	struct wg_softc		*sc = ifp->if_softc;
	struct wg_peer		*peer;
	struct wg_tag		*t;
	struct mbuf		*m;
	SLIST_HEAD(,wg_peer)	 start_list;

	/* We should be OK to modify p_start_list, p_start_onlist in this
	 * function as the interface is not IFXF_MPSAFE and therefore should
	 * only be one instance of this function running at a time. These
	 * values are not modified anywhere else. */
	while ((m = ifq_dequeue(&ifp->if_snd)) != NULL) {
		t = wg_tag_get(m);
		peer = t->t_peer;
		if (mq_enqueue(&peer->p_stage_queue, m) != 0)
			counters_inc(ifp->if_counters, ifc_oqdrops);
		if (!peer->p_start_onlist) {
			SLIST_INSERT_HEAD(&start_list, peer, p_start_list);
			peer->p_start_onlist = 1;
		}
	}
	SLIST_FOREACH(peer, &start_list, p_start_list) {
		if (noise_remote_ready(&peer->p_remote) == 0)
			wg_queue_out(sc, peer);
		else
			wg_timers_event_want_initiation(&peer->p_timers);
		peer->p_start_onlist = 0;
	}
	task_add(wg_crypt_taskq, &sc->sc_encap);
}

int
wg_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *sa,
		struct rtentry *rt)
{
	struct wg_softc	*sc = ifp->if_softc;
	struct wg_peer	*peer;
	struct wg_tag	*t;
	int		 af, ret = EINVAL;

	NET_ASSERT_LOCKED();

	if ((t = wg_tag_get(m)) == NULL) {
		ret = ENOBUFS;
		goto error;
	}

	m->m_pkthdr.ph_family = sa->sa_family;
	if (sa->sa_family == AF_INET) {
		peer = wg_aip_lookup(sc->sc_aip4,
		    &mtod(m, struct ip *)->ip_dst);
	} else if (sa->sa_family == AF_INET6) {
		peer = wg_aip_lookup(sc->sc_aip6,
		    &mtod(m, struct ip6_hdr *)->ip6_dst);
	} else {
		ret = EAFNOSUPPORT;
		goto error;
	}

#if NBPFILTER > 0
	if (sc->sc_if.if_bpf)
		bpf_mtap_af(sc->sc_if.if_bpf, sa->sa_family, m,
		    BPF_DIRECTION_OUT);
#endif

	if (peer == NULL) {
		ret = ENETUNREACH;
		goto error;
	}

	af = peer->p_endpoint.e_remote.r_sa.sa_family;
	if (af != AF_INET && af != AF_INET6) {
		DPRINTF(sc, "No valid endpoint has been configured or "
				"discovered for peer %llu\n", peer->p_id);
		ret = EDESTADDRREQ;
		goto error;
	}

	if (m->m_pkthdr.ph_loopcnt++ > M_MAXLOOP) {
		DPRINTF(sc, "Packet looped");
		ret = ELOOP;
		goto error;
	}

	/* As we hold a reference to peer in the mbuf, we can't handle a
	 * delayed packet without doing some refcnting. If a peer is removed
	 * while a delayed holds a reference, bad things will happen. For the
	 * time being, delayed packets are unsupported. This may be fixed with
	 * another aip_lookup in wg_start, or refcnting as mentioned before. */
	if (m->m_pkthdr.pf.delay > 0) {
		DPRINTF(sc, "PF Delay Unsupported");
		ret = EOPNOTSUPP;
		goto error;
	}

	t->t_peer = peer;
	t->t_mbuf = NULL;
	t->t_done = 0;

	/* We still have an issue with ifq that will count a packet that gets
	 * dropped in wg_start, or not encrypted. These get counted as
	 * ofails or oqdrops, so the packet gets counted twice. */
	return if_enqueue(ifp, m);
error:
	counters_inc(ifp->if_counters, ifc_oerrors);
	m_freem(m);
	return ret;
}

int
wg_ioctl_set(struct wg_softc *sc, struct wg_data_io *data)
{
	struct wg_interface_io	*iface_p, iface_o;
	struct wg_peer_io	*peer_p, peer_o;
	struct wg_aip_io	*aip_p, aip_o;

	struct wg_peer		*peer, *tpeer;
	struct wg_aip		*aip, *taip;

	uint8_t			 public[WG_KEY_SIZE];
	size_t			 i;
	int			 ret;

	rw_enter_write(&sc->sc_lock);

	iface_p = data->wgd_mem;
	if ((ret = copyin(iface_p, &iface_o, sizeof(iface_o))) != 0)
		goto error;

	if (iface_o.i_flags & WG_INTERFACE_REPLACE_PEERS)
		WG_PEERS_FOREACH_SAFE(peer, sc, i, tpeer)
			wg_peer_destroy(peer);

	if (iface_o.i_flags & WG_INTERFACE_HAS_PRIVATE) {
		curve25519_clamp_secret(iface_o.i_private);
		if (!curve25519_generate_public(public, iface_o.i_private))
			goto error;

		if ((peer = wg_peer_lookup(sc, public)) != NULL)
			wg_peer_destroy(peer);

		if (noise_local_set_private(&sc->sc_local,
		    iface_o.i_private) == 0) {
			cookie_checker_update(&sc->sc_cookie, public);
			WG_PEERS_FOREACH(peer, sc, i) {
				noise_remote_clear(&peer->p_remote);
				noise_remote_precompute(&peer->p_remote);
			}
		}
	}

	if ((iface_o.i_flags & WG_INTERFACE_HAS_PORT &&
	      sc->sc_udp_port != htons(iface_o.i_port)) ||
	    (iface_o.i_flags & WG_INTERFACE_HAS_RTABLE &&
	      sc->sc_udp_rtable != iface_o.i_rtable)) {
		if (iface_o.i_flags & WG_INTERFACE_HAS_PORT)
			sc->sc_udp_port = htons(iface_o.i_port);
		if (iface_o.i_flags & WG_INTERFACE_HAS_RTABLE)
			sc->sc_udp_rtable = iface_o.i_rtable;
		NET_LOCK();
		if (ISSET(sc->sc_if.if_flags, IFF_RUNNING)) {
			task_add(net_tq(sc->sc_if.if_index), &sc->sc_down);
			task_add(net_tq(sc->sc_if.if_index), &sc->sc_up);
		}
		NET_UNLOCK();
	}

	for (peer_p = iface_o.i_peers; peer_p != NULL; peer_p = peer_o.p_next) {
		if ((ret = copyin(peer_p, &peer_o, sizeof(peer_o))) != 0)
			goto error;

		/* Peer must have public key */
		if (!(peer_o.p_flags & WG_PEER_HAS_PUBLIC))
			continue;

		/* 0 = latest protocol, 1 = this protocol */
		if (peer_o.p_protocol_version != 0) {
			if (peer_o.p_protocol_version > 1) {
				ret = EPFNOSUPPORT;
				goto error;
			}
		}

		/* Get local public and check that peer key doesn't match */
		if ((ret = noise_local_keys(&sc->sc_local, public, NULL)) == 0 &&
		    bcmp(public, peer_o.p_public, WG_KEY_SIZE) == 0)
			continue;

		/* Lookup peer, or create if it doesn't exist */
		if ((peer = wg_peer_lookup(sc, peer_o.p_public)) == NULL) {
			/* If we want to delete, no need creating a new one.
			 * Also, don't create a new one if we only want to
			 * update. */
			if (peer_o.p_flags & (WG_PEER_REMOVE|WG_PEER_UPDATE))
				continue;

			if ((peer = wg_peer_create(sc,
			    peer_o.p_public)) == NULL) {
				ret = ENOMEM;
				goto error;
			}
		}

		/* Remove peer and continue if specified */
		if (peer_o.p_flags & WG_PEER_REMOVE) {
			wg_peer_destroy(peer);
			continue;
		}

		if (peer_o.p_flags & WG_PEER_HAS_ENDPOINT)
			wg_peer_set_sockaddr(peer, &peer_o.p_sa);

		if (peer_o.p_flags & WG_PEER_HAS_PSK)
			noise_remote_set_psk(&peer->p_remote, peer_o.p_psk);

		if (peer_o.p_flags & WG_PEER_HAS_PKA)
			wg_timers_set_persistent_keepalive(&peer->p_timers,
			    peer_o.p_pka);

		if (peer_o.p_flags & WG_PEER_REPLACE_AIPS) {
			SLIST_FOREACH_SAFE(aip, &peer->p_aip, a_entry, taip) {
				wg_aip_remove(sc, peer, &aip->a_data);
			}
		}

		for (aip_p = peer_o.p_aips; aip_p != NULL; aip_p = aip_o.a_next) {
			if ((ret = copyin(aip_p, &aip_o, sizeof(aip_o))) != 0)
				goto error;
			ret = wg_aip_add(sc, peer, &aip_o.a_data);
			if (ret != 0)
				goto error;
		}
	}
error:
	rw_exit_write(&sc->sc_lock);
	explicit_bzero(&iface_o, sizeof(iface_o));
	explicit_bzero(&peer_o, sizeof(peer_o));
	explicit_bzero(&aip_o, sizeof(aip_o));
	return ret;
}

int
wg_ioctl_get(struct wg_softc *sc, struct wg_data_io *data)
{
	struct wg_interface_io	*iface_p, iface_o;
	struct wg_peer_io	*peer_p, peer_o;
	struct wg_aip_io	*aip_p, aip_o;

	struct wg_peer		*peer;
	struct wg_aip		*aip;

	size_t			 size, i;
	void			*mem;
	int			 ret = 0;

	rw_enter_read(&sc->sc_lock);

	size = sizeof(struct wg_interface_io);
	if (((SIZE_MAX - size) / sizeof(struct wg_peer_io)) < sc->sc_peer_num)
		goto error;
	size += sizeof(struct wg_peer_io) * sc->sc_peer_num;
	if (((SIZE_MAX - size) / sizeof(struct wg_aip_io)) < sc->sc_aip_num)
		goto error;
	size += sizeof(struct wg_aip_io) * sc->sc_aip_num;

	if (data->wgd_size < size)
		goto error;

	bzero(&iface_o, sizeof(iface_o));
	iface_o.i_flags = 0;
	iface_o.i_peers = NULL;

	if (sc->sc_udp_port != 0) {
		iface_o.i_port = ntohs(sc->sc_udp_port);
		iface_o.i_flags |= WG_INTERFACE_HAS_PORT;
	}

	if (sc->sc_udp_rtable != 0) {
		iface_o.i_rtable = sc->sc_udp_rtable;
		iface_o.i_flags |= WG_INTERFACE_HAS_RTABLE;
	}

	if (noise_local_keys(&sc->sc_local, iface_o.i_public,
	    iface_o.i_private) == 0) {
		iface_o.i_flags |= WG_INTERFACE_HAS_PUBLIC;
		iface_o.i_flags |= WG_INTERFACE_HAS_PRIVATE;
	}

	/* Load up the pointer to where iface_o will be */
	iface_p = mem = data->wgd_mem;
	mem = iface_p + 1;

	WG_PEERS_FOREACH(peer, sc, i) {
		bzero(&peer_o, sizeof(peer_o));
		peer_o.p_flags = WG_PEER_HAS_PUBLIC;
		peer_o.p_aips = NULL;
		peer_o.p_protocol_version = 1;

		if (noise_remote_keys(&peer->p_remote, peer_o.p_public,
		    peer_o.p_psk) == 0)
			peer_o.p_flags |= WG_PEER_HAS_PSK;

		if (wg_timers_get_persistent_keepalive(&peer->p_timers,
		    &peer_o.p_pka) == 0)
			peer_o.p_flags |= WG_PEER_HAS_PKA;

		if (wg_peer_get_sockaddr(peer, &peer_o.p_sa) == 0)
			peer_o.p_flags |= WG_PEER_HAS_ENDPOINT;

		mtx_enter(&peer->p_counters_mtx);
		peer_o.p_txbytes = peer->p_counters_tx;
		peer_o.p_rxbytes = peer->p_counters_rx;
		mtx_leave(&peer->p_counters_mtx);

		wg_timers_get_last_handshake(&peer->p_timers,
		    &peer_o.p_last_handshake);

		/* Get pointer, add to linked list */
		peer_o.p_next = iface_o.i_peers;

		peer_p = mem;
		mem = peer_p + 1;
		iface_o.i_peers = peer_p;

		SLIST_FOREACH(aip, &peer->p_aip, a_entry) {
			bzero(&aip_o, sizeof(aip_o));
			aip_o.a_data = aip->a_data;

			/* Get pointer, add to linked list */
			aip_o.a_next = peer_o.p_aips;

			aip_p = mem;
			mem = aip_p + 1;
			peer_o.p_aips = aip_p;

			if ((ret = copyout(&aip_o, aip_p, sizeof(aip_o))) != 0)
				goto error;
		}

		if ((ret = copyout(&peer_o, peer_p, sizeof(peer_o))) != 0)
			goto error;
	}

	if ((ret = copyout(&iface_o, iface_p, sizeof(iface_o))) != 0)
		goto error;
error:
	rw_exit_read(&sc->sc_lock);
	explicit_bzero(&iface_o, sizeof(iface_o));
	explicit_bzero(&peer_o, sizeof(peer_o));
	data->wgd_size = size;
	return ret;
}

int
wg_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifreq	*ifr = (struct ifreq *) data;
	struct wg_softc	*sc = ifp->if_softc;
	int		 ret = 0;

	switch (cmd) {
	case SIOCSWG:
		ret = wg_ioctl_set(sc, (struct wg_data_io *) data);
		break;
	case SIOCGWG:
		ret = wg_ioctl_get(sc, (struct wg_data_io *) data);
		break;
	/* Interface IOCTLs */
	case SIOCSIFADDR:
		SET(ifp->if_flags, IFF_UP);
		/* FALLTHROUGH */
	case SIOCSIFFLAGS:
		if (ISSET(ifp->if_flags, IFF_UP))
			task_add(net_tq(sc->sc_if.if_index), &sc->sc_up);
		else
			task_add(net_tq(sc->sc_if.if_index), &sc->sc_down);
		break;
	case SIOCSIFMTU:
		/* Arbitrary limits */
		if (ifr->ifr_mtu <= 0 || ifr->ifr_mtu > 9000)
			ret = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	default:
		ret = ENOTTY;
	}

	return ret;
}

void
wg_up(struct wg_softc *sc)
{
	struct wg_peer	*peer;
	size_t		 i;

	/* Here we bind to the port specified by sc_udp_port. This function
	 * will run serially, as it is only called from nettq. We still need
	 * to lock if_flags with NET_LOCK and sc_udp_port, sc_udp_rtable,
	 * sc_peers with sc_lock. We want an exclusive lock as wg_bind may
	 * write to sc_udp_port. */
	NET_LOCK();
	if (!ISSET(sc->sc_if.if_flags, IFF_RUNNING)) {
		NET_UNLOCK();
		rw_enter_write(&sc->sc_lock);
		if (wg_bind(sc) == 0) {

			WG_PEERS_FOREACH(peer, sc, i)
				wg_timers_enable(&peer->p_timers);

			rw_exit_write(&sc->sc_lock);
			NET_LOCK();
			SET(sc->sc_if.if_flags, IFF_RUNNING);
		} else {
			rw_exit_write(&sc->sc_lock);
			DPRINTF(sc, "Could not open UDP port\n");
			return;
		}
	}
	NET_UNLOCK();
}

void
wg_down(struct wg_softc *sc)
{
	struct wg_peer	*peer;
	size_t		 i;

	NET_LOCK();
	if (!ISSET(sc->sc_if.if_flags, IFF_RUNNING)) {
		NET_UNLOCK();
		return;
	}
	CLR(sc->sc_if.if_flags, IFF_RUNNING);
	NET_UNLOCK();

	/* We only need a read lock here, as we aren't writing to anything
	 * that isn't granularly locked. */
	rw_enter_read(&sc->sc_lock);

	WG_PEERS_FOREACH(peer, sc, i) {
		mq_purge(&peer->p_stage_queue);
		wg_timers_disable(&peer->p_timers);
	}

	taskq_barrier(wg_handshake_taskq);

	WG_PEERS_FOREACH(peer, sc, i)
		noise_remote_clear(&peer->p_remote);

	wg_unbind(sc);

	rw_exit_read(&sc->sc_lock);
}

int
wg_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet		*ifp;
	struct wg_softc		*sc;
	struct noise_alloc	 local_alloc;

	KERNEL_ASSERT_LOCKED();

	if (wg_counter == 0) {
		wg_handshake_taskq = taskq_create("wg_handshake",
		    2, IPL_NET, TASKQ_MPSAFE);
		wg_crypt_taskq = taskq_create("wg_crypt",
		    ncpus, IPL_NET, TASKQ_MPSAFE);

		if (wg_handshake_taskq == NULL || wg_crypt_taskq == NULL) {
			if (wg_handshake_taskq != NULL)
				taskq_destroy(wg_handshake_taskq);
			if (wg_crypt_taskq != NULL)
				taskq_destroy(wg_crypt_taskq);
			wg_handshake_taskq = NULL;
			wg_crypt_taskq = NULL;
			return ENOTRECOVERABLE;
		}
	}
	wg_counter++;

	if ((sc = malloc(sizeof(*sc), M_DEVBUF, M_NOWAIT | M_ZERO)) == NULL)
		goto ret_00;

	local_alloc.a_arg = sc;
	local_alloc.a_remote_get =
		(struct noise_remote *(*)(void *, uint8_t *))wg_remote_get;
	local_alloc.a_index_set =
		(uint32_t (*)(void *, struct noise_remote *))wg_index_set;
	local_alloc.a_index_drop =
		(void (*)(void *, uint32_t))wg_index_drop;

	/* sc_if is initialised after everything else */
	arc4random_buf(&sc->sc_secret, sizeof(sc->sc_secret));

	rw_init(&sc->sc_lock, "wg");
	noise_local_init(&sc->sc_local, &local_alloc);
	if (cookie_checker_init(&sc->sc_cookie, &wg_ratelimit_pool) != 0)
		goto ret_01;
	sc->sc_udp_port = 0;
	sc->sc_udp_rtable = 0;

	rw_init(&sc->sc_so_lock, "wg_so");
	sc->sc_so4 = NULL;
	sc->sc_so6 = NULL;

	sc->sc_aip_num = 0;
	if ((sc->sc_aip4 = art_alloc(0, 32, 0)) == NULL)
		goto ret_02;
	if ((sc->sc_aip6 = art_alloc(0, 128, 0)) == NULL)
		goto ret_03;

	rw_init(&sc->sc_peer_lock, "wg_peer");
	sc->sc_peer_num = 0;
	if ((sc->sc_peer = hashinit(HASHTABLE_PEER_SIZE, M_DEVBUF,
	    M_NOWAIT, &sc->sc_peer_mask)) == NULL)
		goto ret_04;

	rw_init(&sc->sc_peer_lock, "wg_index");
	if ((sc->sc_index = hashinit(HASHTABLE_INDEX_SIZE, M_DEVBUF,
	    M_NOWAIT, &sc->sc_index_mask)) == NULL)
		goto ret_05;

	task_set(&sc->sc_handshake, (void (*)(void *))wg_handshake_worker, sc);
	mq_init(&sc->sc_handshake_queue, MAX_QUEUED_HANDSHAKES, IPL_NET);

	task_set(&sc->sc_encap, (void (*)(void *))wg_encap_worker, sc);
	task_set(&sc->sc_decap, (void (*)(void *))wg_decap_worker, sc);

	bzero(&sc->sc_encap_ring, sizeof(sc->sc_encap_ring));
	mtx_init(&sc->sc_encap_ring.r_mtx, IPL_NET);
	bzero(&sc->sc_decap_ring, sizeof(sc->sc_decap_ring));
	mtx_init(&sc->sc_decap_ring.r_mtx, IPL_NET);

	task_set(&sc->sc_up, (void (*)(void *))wg_up, sc);
	task_set(&sc->sc_down, (void (*)(void *))wg_down, sc);

	/* We've setup the softc, now we can setup the ifnet */
	ifp = &sc->sc_if;
	ifp->if_softc = sc;

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "wg%d", unit);

	ifp->if_mtu = DEFAULT_MTU;
	ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST;
	ifp->if_xflags = IFXF_CLONED;

	ifp->if_ioctl = wg_ioctl;
	ifp->if_start = wg_start;
	ifp->if_output = wg_output;

	ifp->if_type = IFT_TUNNEL;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);

	if_attach(ifp);
	if_alloc_sadl(ifp);
	if_counters_alloc(ifp);

#if NBPFILTER > 0
	bpfattach(&ifp->if_bpf, ifp, DLT_LOOP, sizeof(uint32_t));
#endif

	DPRINTF(sc, "Interface created\n");

	return 0;
ret_05:
	hashfree(sc->sc_peer, HASHTABLE_PEER_SIZE, M_DEVBUF);
ret_04:
	free(sc->sc_aip6, M_RTABLE, sizeof(*sc->sc_aip6));
ret_03:
	free(sc->sc_aip4, M_RTABLE, sizeof(*sc->sc_aip4));
ret_02:
	cookie_checker_deinit(&sc->sc_cookie);
ret_01:
	free(sc, M_DEVBUF, sizeof(*sc));
ret_00:
	return ENOBUFS;
}
int
wg_clone_destroy(struct ifnet *ifp)
{
	struct wg_softc	*sc = ifp->if_softc;
	struct wg_peer	*peer, *tpeer;
	size_t		 i;

	KERNEL_ASSERT_LOCKED();

	rw_enter_write(&sc->sc_lock);
	WG_PEERS_FOREACH_SAFE(peer, sc, i, tpeer)
		wg_peer_destroy(peer);
	rw_exit_write(&sc->sc_lock);

	wg_unbind(sc);
	if_detach(ifp);

	wg_counter--;
	if (wg_counter == 0) {
		KASSERT(wg_handshake_taskq != NULL && wg_crypt_taskq != NULL);
		taskq_destroy(wg_handshake_taskq);
		taskq_destroy(wg_crypt_taskq);
		wg_handshake_taskq = NULL;
		wg_crypt_taskq = NULL;
	}

	DPRINTF(sc, "Destroyed interface\n");

	hashfree(sc->sc_index, HASHTABLE_INDEX_SIZE, M_DEVBUF);
	hashfree(sc->sc_peer, HASHTABLE_PEER_SIZE, M_DEVBUF);
	free(sc->sc_aip6, M_RTABLE, sizeof(*sc->sc_aip6));
	free(sc->sc_aip4, M_RTABLE, sizeof(*sc->sc_aip4));
	cookie_checker_deinit(&sc->sc_cookie);
	free(sc, M_DEVBUF, sizeof(*sc));
	return 0;
}

void
wgattach(int nwg)
{
	if_clone_attach(&wg_cloner);

	pool_init(&wg_aip_pool, sizeof(struct wg_aip), 0,
			IPL_NET, 0, "wgaip", NULL);
	pool_init(&wg_peer_pool, sizeof(struct wg_peer), 0,
			IPL_NET, 0, "wgpeer", NULL);
	pool_init(&wg_ratelimit_pool, sizeof(struct ratelimit), 0,
			IPL_NET, 0, "wgratelimit", NULL);
}
