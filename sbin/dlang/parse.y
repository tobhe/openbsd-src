/*
 * Copyright (c) 2019 Tobias Heider <tobias.heider@stusta.de>
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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

%{
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "dlang.h"

static void	 print_probes();
static void	 cleanup_probes();

static void	 yyerror(const char *, ...);
static int	 yylex(void);

const char	*pbuf;
size_t		 plen;
size_t		 pindex;

struct probe	**probes;
int		  nprobes;
static int	  maxprobes;

int		  parse_errors = 0;

struct probe {
	const char	*provider;
	const char	*module;
	const char	*function;
	const char	*action;
};

typedef struct {
	union {
		struct {
			const char	*provider;
			const char	*module;
			const char	*function;
		};
		int64_t		 number;
		uint8_t		 timeunit;
		const char	*string;
	};
	int	lineno;
	int	colno;
} yystype;
#define YYSTYPE yystype

%}

%token	THZ TS TMS TUS UUID EQUALS NOT_EQUALS NUMBER STRING PID

%%

grammar		: /* empty */
		| grammar rule
		;

rule		: /* empty */
		| probe filter_block instruction {
			struct probe *p;
			p = calloc(1, sizeof(*p));
			if (!p)
				errx(1, "can't allocate probe");
			p->provider = $1.provider;
			p->module= $1.module;
			p->function = $1.function;
			p->action = $3.string;
			if (nprobes == maxprobes) {
				if (maxprobes == 0)
					maxprobes = 63;
				else
					maxprobes *= 2;
				if (!(probes = reallocarray(probes, maxprobes,
				    sizeof(*probes))))
					errx(1, "can't allocate probes");

			}
			probes[nprobes++] = p;
		}
		;

filter_block	: /* empty */
		| '/' variable eq_comp NUMBER '/'
		| '/' NUMBER eq_comp variable '/'
		;

variable	: UUID
		| PID
		;

eq_comp		: EQUALS
		| NOT_EQUALS
		;

probe		: opt_string ':' opt_string ':' opt_string {
			$$.provider = $1.string;
			$$.module = $3.string;
			$$.function = $5.string;
		}
		;

opt_string	: /* empty */ {
			$$.string = "";
		}
		| STRING {
			$$.string = $1.string;
		}

instruction	: '{' STRING ';' '}' { $$.string = $2.string; }
		;

%%

static struct keyword {
	const char	*word;
	int		 token;
} keywords[] = {
	{ "pid",	PID},
	{ "uuid",	UUID},
	{ "==",		EQUALS},
	{ "!=",		NOT_EQUALS}
};


int
print_probe(uint8_t time, int64_t val)
{
	printf("Unit: %"PRIu8", Val: %"PRIi64"\n", time, val);
	return 0;
}

int
lgetc(void)
{
	if (pbuf != NULL) {
		if(pindex < plen)
			return pbuf[pindex++];
	}
	return EOF;
}

void
lungetc(void)
{
	if (pbuf != NULL && pindex > 0) {
		pindex--;
	}
}

int
yylex(void)
{
	unsigned char	*ebuf, *p, *str;
	unsigned char	 buf[1024];
	int		 i, c;
	int		 qpos = -1;
	int		 nonkw = 0;

	p = buf;
	ebuf = buf + sizeof(buf);

repeat:
	/* skip whitespaces */
	for (c = lgetc(); c == ' ' || c == '\t' || c == '\n'; c = lgetc())
		yylval.colno++;

	switch (c) {
	case '{':
	case '}':
	case ':':
	case ';':
	case '/':
		return c;
	case EOF:
		return 0;
	}

	/* parsing next word */
	for (;; c = lgetc(), yylval.colno++) {
		switch(c) {
		case ':':
		case ';':
		case '\t':
		case '\n':
		case ' ':
		case '/':
		case EOF:
			goto eow;
			break;
		}

		*p++ = c;
		if (p == ebuf) {
			yyerror("too long line");
			p = buf;
		}
	}

eow:
	*p = '\0';
	if (c != EOF)
		lungetc();
	if (p == buf) {
		/*
		 * There could be a number of reasons for empty buffer,
		 * and we handle all of them here, to avoid cluttering
		 * the main loop.
		 */
		if (c == EOF)
			goto eof;
		else if (qpos == -1)    /* accept, e.g., empty args: cmd foo args "" */
			goto repeat;
	}

	/* handle keywords */
	if (!nonkw) {
		for (i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
				if (strcmp(buf, keywords[i].word) == 0)
					return keywords[i].token;
		}
	}

	/* handle strings */
	if ((str = strdup(buf)) == NULL)
		err(1, "%s", __func__);
	yylval.string = str;
	return STRING;

eof:
	return 0;
}

void
yyerror(const char *fmt, ...)
{
	va_list	va;

	fprintf(stderr, "dlang: ");
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, " at line %d\n", yylval.lineno + 1);
	parse_errors++;
}

int
parse_script(const char *str, size_t len, int debug)
{
	int	ret;

	if (debug > 1)
		yydebug = 1;
	pbuf = str;
	plen = len;
	pindex = 0;
	yyparse();
	if (debug && !parse_errors) {
		print_probes();
	}

	ret = parse_errors;

	parse_errors = 0;
	cleanup_probes();
	return ret;
}

static void
print_probes()
{
	struct probe	*p;
	int		 i;

	printf("%8s\t%8s\t%8s\t\t%8s\n", "Provider", "Module", "Function", "Action");
	printf("================================================================\n");
	for (i = 0; i < nprobes; i++) {
		p = probes[i];
		printf("%8s\t%8s\t%8s\t\t%8s\n", p->provider, p->module,
		    p->function, p->action);
	}
	printf("\n");
}

static void
cleanup_probes()
{
	struct probe	*p;
	int		 i;

	if (probes == NULL) {
		return;
	}

	for (i = 0; i < nprobes; i++) {
		p = probes[i];
		if (p)
			free(p);
			p = NULL;
	}
	free(probes);
	nprobes = 0;
	maxprobes = 0;
	probes = NULL;
}
