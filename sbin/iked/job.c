/*
 * Copyright (c) 2014 Pedro Martelletto
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

/*
 * This file implements a thin shell around libevent that allows processes to
 * be run as "jobs" under specified timeouts.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <event.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "job.h"

LIST_HEAD(, job) job_list;

void
job_init(void)
{
	LIST_INIT(&job_list);
}

int
job_eval(pid_t pid, int status)
{
	struct job	*j;

	LIST_FOREACH(j, &job_list, job_entry)
		if (j->pid == pid)
			break;

	if (j == NULL)
		return (-1);

	event_del(&j->ev);
	LIST_REMOVE(j, job_entry);

	j->callback(0, status, j->arg);

	return (0);
}

extern char	**environ;

__dead static void
job_child(struct job *j, int pfd)
{
	char	ok[2];
	ssize_t	n;

	n = read(pfd, ok, sizeof(ok));
	if (n != sizeof(ok) || ok[0] != 'o' || ok[1] != 'k')
		exit(255);
	close(pfd);

	execve(j->argv[0], j->argv, environ);

	exit(255);
}

static void
job_timeout(__unused int fd, __unused short ev, void *arg)
{
	struct job	*j = arg;

	event_del(&j->ev);
	LIST_REMOVE(j, job_entry);

	j->callback(1, 0, j->arg);
}

static int
job_parent(struct job *j, int cfd, struct timeval *tv)
{
	event_set(&j->ev, -1, EV_TIMEOUT, job_timeout, j);
	event_add(&j->ev, tv);

	LIST_INSERT_HEAD(&job_list, j, job_entry);
	write(cfd, "ok", strlen("ok"));
	close(cfd);

	return (0);
}

int
job_set(struct job *j, int nargs, char *path, ...)
{
	va_list	ap;
	int	i;

	if (nargs > JOB_MAXARG)
		return (-1);

	va_start(ap, path);
	j->argv[0] = path;
	for (i = 0; i < nargs; i++)
		j->argv[i + 1] = va_arg(ap, char *);
	va_end(ap);

	j->argv[i + 1] = NULL;

	return (0);
}

int
job_dispatch(struct job *j, void (*callback)(int, int, void *), void *arg,
    struct timeval *tv)
{
	int	fd[2];
	pid_t	pid;

	if (pipe(fd) < 0)
		return (-1);

	switch (pid = fork()) {
	case -1:
		close(fd[0]);
		close(fd[1]);
		return (-1);
	case 0:
		close(fd[1]);
		job_child(j, fd[0]);
		/* NOTREACHED */
	default:
		close(fd[0]);
		j->pid = pid;
		j->callback = callback;
		j->arg = arg;
		return (job_parent(j, fd[1], tv));
	}

	/* NOTREACHED */
}

int
job_kill(struct job *j, int sig)
{
	return (kill(j->pid, sig));
}
