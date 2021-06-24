/*
 * sydbox/sydfmt.c
 *
 * sydbox magic command formatter
 *
 * Copyright (c) 2012, 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydconf.h"
#include "compiler.h"

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "sydfmt"

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pink.h"

static int puts_exec(char **argv);

struct key {
	const char *cmd;
	int (*puts) (char **argv);
};

static const struct key key_table[] = {
	{"exec", puts_exec},
	{NULL, NULL},
};

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION"\n");
}

SYD_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- sydbox magic command formatter \n\
usage: "PACKAGE" [-hv]\n\
       "PACKAGE" exec [--] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
\n\
Hey you, out there on the road,\n\
Always doing what you're told,\n\
Can you help me?\n\
\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}

#define oops(...) \
	do { \
		fprintf(stderr, PACKAGE": "); \
		fprintf(stderr, __VA_ARGS__); \
		fputc('\n', stderr); \
	} while (0)

static int puts_exec(char **argv)
{
	int i = 0;

	if (argv[0] == NULL)
		usage(stderr, EXIT_FAILURE);
	if (!strcmp(argv[0], "--"))
		i = 1;
	if (argv[i] == NULL)
		usage(stderr, EXIT_FAILURE);

	printf("%s/cmd/exec%c", SYDBOX_MAGIC_PREFIX, SYDBOX_MAGIC_EXEC_CHAR);
	for (;argv[i]; i++) {
		printf("%s", argv[i]);
		if (argv[i+1] != NULL)
			fputc(037, stdout); /* unit separator */
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	int i;

	if (argv[1] == NULL)
		usage(stderr, EXIT_FAILURE);

	if (argv[1][0] == '-') {
		if (!strcmp(argv[1], "-h") ||
		    !strcmp(argv[1], "--help"))
			usage(stdout, EXIT_SUCCESS);
		if (!strcmp(argv[1], "-v") ||
		    !strcmp(argv[1], "--version")) {
			about();
			return EXIT_SUCCESS;
		}
	}

	for (i = 0; key_table[i].cmd; i++) {
		if (!strcmp(key_table[i].cmd, argv[1]))
			return key_table[i].puts(&argv[2]);
	}
	oops("invalid command `%s'", argv[1]);
	usage(stderr, EXIT_FAILURE);
}
