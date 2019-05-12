/*
 * Copyright (c) 2019 Tobias Heider <tobias.heider@stusta.de>
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

#include <string.h>

struct dlang_req {
	unsigned int	 pid	: 1;	/* Process ID*/
	unsigned int	 tid	: 1;	/* Thread ID */
	unsigned int	 uid	: 1;	/* User ID */
	unsigned int	 gid	: 1;	/* Group ID */
	unsigned int	 nsec	: 1;	/* Nanoseconds timestamp */
	unsigned int	 cpu	: 1;	/* Processor ID */
	unsigned int	 comm	: 1;	/* Process name */
	unsigned int	 kstack	: 1;	/* Kernel stack trace */
	unsigned int	 ustack	: 1;	/* User stack trace */
	unsigned int	 args	: 1;	/* Function arguments */
	unsigned int	 func	: 1;	/* Function name */
};

struct dlang_res {
	int	  pid;		/* Process ID*/
	int	  tid;		/* Thread ID */
	int	  uid;		/* User ID */
	int	  gid;		/* Group ID */
	int	  nsec;		/* Nanoseconds timestamp */
	int	  cpu;		/* Processor ID */
	int	  comm;		/* Process name */
	void	**kstack;	/* Kernel stack trace */
	void	**ustack;	/* User stack trace */
	char	**args;		/* Function arguments */
	char	 *func;		/* Function name */
};

#define DLANG_FUNCTION_STACKTRACE	(1)

#define DLANG_OPERATOR_EQUAL		(1)
#define DLANG_OPERATOR_NOT_EQUAL	(2)

#define DLANG_ATTRIBUTE_UUID	(1)
#define DLANG_ATTRIBUTE_PID	(2)

int	parse_script(const char *, size_t, int);
