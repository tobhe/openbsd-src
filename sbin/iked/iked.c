/*	$OpenBSD: iked.c,v 1.47 2020/08/24 21:00:21 tobhe Exp $	*/

/*
 * Copyright (c) 2019 Tobias Heider <tobias.heider@stusta.de>
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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <event.h>

#include "iked.h"
#include "ikev2.h"
#include "job.h"

__dead void usage(void);

void	 parent_shutdown(struct iked *);
void	 parent_sig_handler(int, short, void *);
int	 parent_dispatch_ca(int, struct privsep_proc *, struct imsg *);
int	 parent_dispatch_control(int, struct privsep_proc *, struct imsg *);
int	 parent_dispatch_ikev2(int, struct privsep_proc *, struct imsg *);
int	 parent_configure(struct iked *);

static struct privsep_proc procs[] = {
	{ "ca",		PROC_CERT,	parent_dispatch_ca, caproc, IKED_CA },
	{ "control",	PROC_CONTROL,	parent_dispatch_control, control },
	{ "ikev2",	PROC_IKEV2,	parent_dispatch_ikev2, ikev2 }
};

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-dnSTtv] [-D macro=value] "
	    "[-f file] [-p udpencap_port]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		 c;
	int		 debug = 0, verbose = 0;
	int		 opts = 0;
	enum natt_mode	 natt_mode = NATT_DEFAULT;
	in_port_t	 port = IKED_NATT_PORT;
	const char	*conffile = IKED_CONFIG;
	struct iked	*env = NULL;
	struct privsep	*ps;

	log_init(1, LOG_DAEMON);

	while ((c = getopt(argc, argv, "6dD:nf:p:vSTt")) != -1) {
		switch (c) {
		case '6':
			log_warnx("the -6 option is ignored and will be "
			    "removed in the future.");
			break;
		case 'd':
			debug++;
			break;
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'n':
			debug = 1;
			opts |= IKED_OPT_NOACTION;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'v':
			verbose++;
			opts |= IKED_OPT_VERBOSE;
			break;
		case 'S':
			opts |= IKED_OPT_PASSIVE;
			break;
		case 'T':
			if (natt_mode == NATT_FORCE)
				errx(1, "-T and -t/-p are mutually exclusive");
			natt_mode = NATT_DISABLE;
			break;
		case 't':
			if (natt_mode == NATT_DISABLE)
				errx(1, "-T and -t are mutually exclusive");
			natt_mode = NATT_FORCE;
			break;
		case 'p':
			if (natt_mode == NATT_DISABLE)
				errx(1, "-T and -p are mutually exclusive");
			port = atoi(optarg);
			natt_mode = NATT_FORCE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0)
		usage();

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("calloc: env");

	env->sc_opts = opts;
	env->sc_nattmode = natt_mode;
	env->sc_nattport = port;

	ps = &env->sc_ps;
	ps->ps_env = env;
	TAILQ_INIT(&ps->ps_rcsocks);

	if (strlcpy(env->sc_conffile, conffile, PATH_MAX) >= PATH_MAX)
		errx(1, "config file exceeds PATH_MAX");

	ca_sslinit();
	policy_init(env);

	/* check for root privileges */
	if (geteuid())
		errx(1, "need root privileges");

	if ((ps->ps_pw =  getpwnam(IKED_USER)) == NULL)
		errx(1, "unknown user %s", IKED_USER);

	/* Configure the control socket */
	ps->ps_csock.cs_name = IKED_SOCKET;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (opts & IKED_OPT_NOACTION)
		ps->ps_noaction = 1;

	if (!debug && daemon(0, 0) == -1)
		err(1, "failed to daemonize");

	group_init();

	ps->ps_ninstances = 1;
	proc_init(ps, procs, nitems(procs));

	setproctitle("parent");
	log_procinit("parent");

	event_init();
	job_init();

	signal_set(&ps->ps_evsigint, SIGINT, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigchld, SIGCHLD, parent_sig_handler, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigpipe, SIGPIPE, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, parent_sig_handler, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsigchld, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigpipe, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);

	proc_listen(ps, procs, nitems(procs));

	if (parent_configure(env) == -1)
		fatalx("configuration failed");

	event_dispatch();

	log_debug("%d parent exiting", getpid());

	return (0);
}

int
parent_configure(struct iked *env)
{
	struct sockaddr_storage	 ss;

	if (parse_config(env->sc_conffile, env) == -1) {
		proc_kill(&env->sc_ps);
		exit(1);
	}

	if (env->sc_opts & IKED_OPT_NOACTION) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(&env->sc_ps);
		exit(0);
	}

	env->sc_pfkey = -1;
	config_setpfkey(env, PROC_IKEV2);

	/* Send private and public keys to cert after forking the children */
	if (config_setkeys(env) == -1)
		fatalx("%s: failed to send keys", __func__);
	config_setreset(env, RESET_CA, PROC_CERT);

	/* Now compile the policies and calculate skip steps */
	config_setcompile(env, PROC_IKEV2);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET;

	/* see comment on config_setsocket() */
	if (env->sc_nattmode != NATT_FORCE)
		config_setsocket(env, &ss, htons(IKED_IKE_PORT), PROC_IKEV2);
	if (env->sc_nattmode != NATT_DISABLE)
		config_setsocket(env, &ss, htons(env->sc_nattport), PROC_IKEV2);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET6;

	if (env->sc_nattmode != NATT_FORCE)
		config_setsocket(env, &ss, htons(IKED_IKE_PORT), PROC_IKEV2);
	if (env->sc_nattmode != NATT_DISABLE)
		config_setsocket(env, &ss, htons(env->sc_nattport), PROC_IKEV2);

	/*
	 * pledge in the parent process:
	 * It has to run fairly late to allow forking the processes and
	 * opening the PFKEY socket and the listening UDP sockets (once)
	 * that need the bypass ioctls that are never allowed by pledge.
	 *
	 * Other flags:
	 * stdio - for malloc and basic I/O including events.
	 * rpath - for reload to open and read the configuration files.
	 * proc - run kill to terminate its children safely.
	 * dns - for reload and ocsp connect.
	 * inet - for ocsp connect.
	 * route - for using interfaces in iked.conf (SIOCGIFGMEMB)
	 * sendfd - for ocsp sockets.
	 * exec - fro aclhook
	 */
	if (pledge("stdio rpath proc dns inet route sendfd exec", NULL) == -1)
		fatal("pledge");

	config_setstatic(env);
	config_setcoupled(env, env->sc_decoupled ? 0 : 1);
	config_setocsp(env);
	config_setaclhook(env);
	/* Must be last */
	config_setmode(env, env->sc_passive ? 1 : 0);

	return (0);
}

void
parent_reload(struct iked *env, int reset, const char *filename)
{
	/* Switch back to the default config file */
	if (filename == NULL || *filename == '\0')
		filename = env->sc_conffile;

	log_debug("%s: level %d config file %s", __func__, reset, filename);

	if (reset == RESET_RELOAD) {
		config_setreset(env, RESET_POLICY, PROC_IKEV2);
		if (config_setkeys(env) == -1)
			fatalx("%s: failed to send keys", __func__);
		config_setreset(env, RESET_CA, PROC_CERT);

		if (parse_config(filename, env) == -1) {
			log_debug("%s: failed to load config file %s",
			    __func__, filename);
		}

		/* Re-compile policies and skip steps */
		config_setcompile(env, PROC_IKEV2);

		config_setstatic(env);
		config_setcoupled(env, env->sc_decoupled ? 0 : 1);
		config_setocsp(env);
		config_setaclhook(env);
 		/* Must be last */
		config_setmode(env, env->sc_passive ? 1 : 0);
	} else {
		config_setreset(env, reset, PROC_IKEV2);
		config_setreset(env, reset, PROC_CERT);
	}
}

void
parent_sig_handler(int sig, short event, void *arg)
{
	struct privsep	*ps = arg;
	int		 die = 0, status, fail, id;
	pid_t		 pid;
	char		*cause;

	switch (sig) {
	case SIGHUP:
		log_info("%s: reload requested with SIGHUP", __func__);

		/*
		 * This is safe because libevent uses async signal handlers
		 * that run in the event loop and not in signal context.
		 */
		parent_reload(ps->ps_env, 0, NULL);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		die = 1;
		/* FALLTHROUGH */
	case SIGCHLD:
		do {
			int len;

			pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0)
				continue;
			/*
			 * assume it's one of our procs, and look for them
			 * first.
			 */
			if (__predict_true(job_eval(pid, status) == 0))
				continue;

			fail = 0;
			if (WIFSIGNALED(status)) {
				fail = 1;
				len = asprintf(&cause, "terminated; signal %d",
				    WTERMSIG(status));
			} else if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) != 0) {
					fail = 1;
					len = asprintf(&cause,
					    "exited abnormally");
				} else
					len = asprintf(&cause, "exited okay");
			} else
				fatalx("unexpected cause of SIGCHLD");

			if (len == -1)
				fatal("asprintf");

			die = 1;

			for (id = 0; id < PROC_MAX; id++)
				if (pid == ps->ps_pid[id]) {
					if (fail)
						log_warnx("lost child: %s %s",
						    ps->ps_title[id], cause);
					break;
				}
			/*
			 * this can happen in case of a job_dispatch() timeout.
			 * only die if one of the iked procs actually exited.
			 */
			if (id == PROC_MAX)
				die = 0;

			free(cause);
		} while (pid > 0 || (pid == -1 && errno == EINTR));

		if (die)
			parent_shutdown(ps->ps_env);
		break;
	default:
		fatalx("unexpected signal");
	}
}

int
parent_dispatch_ca(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = p->p_ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_OCSP_FD:
		ocsp_connect(env, imsg);
		break;
	default:
		return (-1);
	}

	return (0);
}

struct iked_job {
	struct iked	*env;
	struct ibuf	*ibuf;
	char		*tokens[6]; /* here to aid debugging */
	char		*tag;
	struct job	 j;
	struct iked_sahdr sh;
};

static int
parent_aclhook_fail(struct iked *env, void *ptr, uint16_t len)
{
	return (proc_compose(&env->sc_ps, PROC_IKEV2, IMSG_ACLHOOK_FAIL,
	    ptr, len));
}

static int
parent_aclhook_ok(struct iked *env, void *ptr, uint16_t len)
{
	return (proc_compose(&env->sc_ps, PROC_IKEV2, IMSG_ACLHOOK_OK,
	    ptr, len));
}

static void
parent_aclhook_callback(int timeout, int status, void *arg)
{
	struct iked_job	*ij = arg;
	void		*ptr = ibuf_data(ij->ibuf);
	uint16_t	 len = ibuf_length(ij->ibuf); /* XXX overflow */
	int		 ok = -1;

	if (timeout) {
		log_warnx("%s: aclhook timeout (%s, %s, %s)",
		    SPI_SH(&ij->sh, __func__),
		    ij->tokens[0], ij->tokens[1], ij->tokens[2]);
		job_kill(&ij->j, SIGTERM);
	} else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		ok = 0;

	if (ok == -1) {
		log_info("%s: aclhook failed (%s, %s, %s) status %d",
		    SPI_SH(&ij->sh, __func__),
		    ij->tokens[0], ij->tokens[1], ij->tokens[2],
		    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		parent_aclhook_fail(ij->env, ptr, len);
	} else {
		log_debug("%s: aclhook successful (%s, %s, %s)",
		    SPI_SH(&ij->sh, __func__),
		    ij->tokens[0], ij->tokens[1], ij->tokens[2]);
		parent_aclhook_ok(ij->env, ptr, len);
	}

	free(ij->tokens[0]);
	free(ij->tokens[1]);
	free(ij->tokens[2]);
	free(ij->tokens[3]);
	free(ij->tokens[4]);
	free(ij->tokens[5]);
	free(ij->tag);
	ibuf_free(ij->ibuf);
	free(ij);
}

/*
 * Parent notification that a certificate has been validated.
 *
 * The notification message is composed of two tokens.  These tokens are
 * alphanumeric, with an optional '.'.
 */
static int
parent_aclhook(struct iked *env, struct imsg *imsg)
{
	char		*tokens[JOB_TOKENS];
	char		*tag = NULL;
	uint32_t	 tokens_length[JOB_TOKENS];
	uint8_t		*msgptr = imsg->data;
	size_t		 msgsiz = IMSG_DATA_SIZE(imsg);
	struct		 iked_sahdr sh;
	struct		 iked_job *ij = NULL;
	struct		 timeval tv;
	int		 i;

	if (msgsiz < sizeof(sh) + sizeof(tokens_length))
		fatalx("bad length imsg received");

	for (i = 0; i < JOB_TOKENS; i++)
		tokens[i] = NULL;

	memcpy(&sh, msgptr, sizeof(sh));
	msgptr += sizeof(sh);
	msgsiz -= sizeof(sh);

	memcpy(&tokens_length, msgptr, sizeof(tokens_length));
	msgptr += sizeof(tokens_length);
	msgsiz -= sizeof(tokens_length);

	for (i = 0; i < JOB_TOKENS; i++) {
		if (msgsiz < tokens_length[i])
			fatalx("bad length token received (%d) %zu %u", i,
			    msgsiz, tokens_length[i]);
		msgsiz -= tokens_length[i];
	}
	if (msgsiz != 0)
		fatalx("bad length imsg received");

	if ((ij = calloc(1, sizeof(*ij))) == NULL) {
		log_warn("%s: calloc", SPI_SH(&sh, __func__));
		goto bail;
	}
	memcpy(&ij->sh, &sh, sizeof(sh));
	if ((tag = strdup(SPI_SH(&ij->sh, NULL))) == NULL) {
		log_warn("%s: strdup", SPI_SH(&sh, __func__));
		goto bail;
	}

	if ((ij->ibuf = ibuf_new(imsg->data, IMSG_DATA_SIZE(imsg))) == NULL) {
		log_warnx("%s: ibuf_new", SPI_SH(&ij->sh, __func__));
		goto bail;
	}

	for (i = 0; i < JOB_TOKENS; i++) {
		if ((tokens[i] = calloc(tokens_length[i] + 1, sizeof(char)))
		    == NULL) {
			log_warn("%s: calloc", SPI_SH(&sh, __func__));
			goto bail;
		}
		memcpy(tokens[i], msgptr, tokens_length[i]);
		msgptr += tokens_length[i];
		ij->tokens[i] = tokens[i];
	}

	/* NB: changing the order of tokens breaks the API */
	ij->env = env;
	ij->tag = tag;
	if (job_set(&ij->j, JOB_TOKENS+1, env->sc_aclhook, tokens[0], tokens[1],
	    tokens[2], tokens[3], tokens[4], tokens[5], tag, tokens[6]) < 0) {
		log_warnx("%s: job_set", SPI_SH(&ij->sh, __func__));
		goto bail;
	}

	tv.tv_sec = env->sc_aclhook_timeout;
	tv.tv_usec = 0;

	if (job_dispatch(&ij->j, parent_aclhook_callback, ij, &tv) < 0) {
		log_warnx("%s: job_dispatch", SPI_SH(&ij->sh, __func__));
		goto bail;
	}

	return (0);

bail:
	for (i = 0; i < JOB_TOKENS; i++)
		free(tokens[i]);
	free(tag);
	free(ij);

	return (-1);
}
int
parent_dispatch_ikev2(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	switch (imsg->hdr.type) {
	case IMSG_ACLHOOK_EXEC:
		if (parent_aclhook(p->p_ps->ps_env, imsg) < 0) {
			log_debug("%s: parent_aclhook failed", __func__);
			parent_aclhook_fail(p->p_ps->ps_env, imsg->data,
			    IMSG_DATA_SIZE(imsg));
		}
		return (0);
	default:
		return (-1);
	}

	return (0);
}

int
parent_dispatch_control(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = p->p_ps->ps_env;
	int		 v;
	char		*str = NULL;
	unsigned int	 type = imsg->hdr.type;

	switch (type) {
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &v);
		memcpy(&v, imsg->data, sizeof(v));
		parent_reload(env, v, NULL);
		break;
	case IMSG_CTL_COUPLE:
	case IMSG_CTL_DECOUPLE:
	case IMSG_CTL_ACTIVE:
	case IMSG_CTL_PASSIVE:
		proc_compose(&env->sc_ps, PROC_IKEV2, type, NULL, 0);
		break;
	case IMSG_CTL_RELOAD:
		if (IMSG_DATA_SIZE(imsg) > 0)
			str = get_string(imsg->data, IMSG_DATA_SIZE(imsg));
		parent_reload(env, 0, str);
		free(str);
		break;
	case IMSG_CTL_VERBOSE:
		proc_forward_imsg(&env->sc_ps, imsg, PROC_IKEV2, -1);
		proc_forward_imsg(&env->sc_ps, imsg, PROC_CERT, -1);

		/* return 1 to let proc.c handle it locally */
		return (1);
	default:
		return (-1);
	}

	return (0);
}

void
parent_shutdown(struct iked *env)
{
	proc_kill(&env->sc_ps);

	free(env);

	log_warnx("parent terminating");
	exit(0);
}
