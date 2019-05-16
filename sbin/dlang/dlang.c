/*	$OpenBSD$	*/
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/lhash.h>

#include "dlang.h"

__dead void usage(void);

static void print_probes(void);

/* XXX: Get list from kernel */
struct probe_el {
	size_t		 id;
	const char	*provider;
	const char	*module;
	const char	*function;
	const char	*name;
} probes_list[] = {
	{ 0, "dt", "profile", "s", "" },
	{ 1, "dt", "profile", "ms", "" },
	{ 2, "dt", "profile", "us", "" },
	{ 3, "dt", "profile", "us", "" },
	{ 4, "dt", "profile", "hz", "" },
	{ 5, "dt", "interval", "s", "" },
	{ 6, "dt", "interval", "ms", "" },
	{ 7, "dt", "interval", "us", "" },
	{ 8, "dt", "interval", "us", "" },
};
int	probes_num = 9;

void
usage(void) {
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-d] [-e script]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[]) {

	int		ch, dflag = 0;
	const char	*script = NULL;

	while ((ch = getopt(argc, argv, "de:l")) != -1) {
		switch (ch){
		case 'd':
			dflag = 2;
			break;
		case 'e':
			script = optarg;
			break;
		case 'l':
			print_probes();
			exit(1);
		default:
			usage();
		}
	}
	if (script == NULL)
		usage();

	parse_script(script, strlen(script), dflag);
	return 0;
}

void print_probes() {
	struct probe_el	*p;
	int		 i;

	printf("%4s %8s %8s %8s %-8s\n","ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");
	for (i = 0; i < probes_num; i++) {
		p = &probes_list[i];
		printf("%4zu %8s %8s %8s %-8s\n",p->id, p->provider, p->module,
		    p->function, p->name);
	}
	printf("\n");
}
