/*
 * sydbox/syd-run.c
 * Syd's interface to Tarot Decks
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <syd/syd.h>

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "syd-TAROT"

static void print_tarot(void);

static void about(void);
static void usage(FILE *outfp, int code)
	SYD_GCC_ATTR((noreturn));

static void print_tarot(void)
{
	int r;
	char *card;

	if ((r = syd_tarot_draw(&card)) < 0) {
		perror("syd_tarot_draw");
		return;
	}

	printf("%s\n", card);
	free(card);
}

static void about(void)
{
	printf(SYD_WARN PACKAGE"-"VERSION GITVERSION SYD_RESET "\n");
}

SYD_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION"\n\
Syd's interface to Tarot Decks\n\
usage: "PACKAGE" [-hv]\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
\n\
Given no arguments, prints a Tarot Card.\n\
\n"SYD_HELPME);
	exit(code);
}

int main(int argc, char **argv)
{
	if (argc <= 1) {
		print_tarot();
		return EXIT_SUCCESS;
	}
	if (argv[1][0] == '-') {
		if (!strcmp(argv[1], "-h") ||
		    !strcmp(argv[1], "--help"))
			usage(stdout, EXIT_SUCCESS);
		if (!strcmp(argv[1], "-v") ||
		    !strcmp(argv[1], "--version")) {
			about();
			syd_about(stdout);
			return EXIT_SUCCESS;
		}
	}
	print_tarot();
	return EXIT_SUCCESS;
}
