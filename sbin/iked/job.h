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

#ifndef _JOB_H
#define _JOB_H

#define JOB_MAXARG	16
#define JOB_TOKENS	7

struct job {
	/* account for progname + terminating NULL in argv */
	char		 *argv[JOB_MAXARG + 2];
	void		(*callback)(int, int, void *);
	void		 *arg;
	LIST_ENTRY(job)	  job_entry;
	pid_t		  pid;
	struct event	  ev;
};

void	job_init(void);
int	job_eval(pid_t, int);
int	job_set(struct job *, int, char *, ...);
int	job_dispatch(struct job *, void (*)(int, int, void *), void *,
	    struct timeval *);
int	job_kill(struct job *, int);

#endif /* _JOB_H */
