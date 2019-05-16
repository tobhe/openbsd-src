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

/*
 * Flags to request variables from kernel
 */
#define DT_REQUEST_PID		  (0x1)
#define DT_REQUEST_TID		  (0x2)
#define DT_REQUEST_UID		  (0x4)
#define DT_REQUEST_GID		  (0x8)
#define DT_REQUEST_NSEC		 (0x10)
#define DT_REQUEST_CPU		 (0x20)
#define DT_REQUEST_COMM		 (0x40)
#define DT_REQUEST_KSTACK	 (0x80)
#define DT_REQUEST_USTACK	(0x100)
#define DT_REQUEST_ARGS		(0x200)
#define DT_REQUEST_FUNC		(0x400)

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
