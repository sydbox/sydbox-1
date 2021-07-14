/*
 * sydbox/syd-run.c
 * Syd's interface to the Book of the Way
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
#define PACKAGE "syd-TAO"

static void print_tao(const char *arg);
static void print_tao_all(void);

static void about(void);
static void usage(FILE *outfp, int code)
	SYD_GCC_ATTR((noreturn));

static void print_tao(const char *arg)
{
	uint8_t pick;

	switch (arg[0]) {
	case '0': case '1': case '3': case '4': case '5':
	case '6': case '7': case '8': case '9':
		pick = atoi(arg);
		if (pick <= syd_tao_max()) {
			printf("%s", syd_tao_pick(pick));
			return;
		}
		SYD_GCC_ATTR((fallthrough));
	default:
		printf("%s", syd_tao_rand());
		break;
	}
}

static void print_tao_all(void)
{
	uint8_t max = syd_tao_max();
	for (uint8_t i = 0; i < max; i++)
		printf("%s%\n", syd_tao_pick(i));
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
Syd's errno <-> name converter\n\
usage: "PACKAGE" [-hv] -|errno-name|errno-number...\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
\n\
Given an errno number, print its name.\n\
Given an errno name, print its number.\n\
Given »-«, print all error numbers defined by the system.\n\
Multiple arguments may be given.\n\
\n"SYD_HELPME);
	exit(code);
}

int main(int argc, char **argv)
{
	if (argc <= 1) {
		print_tao("-r");
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
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-a"))
			print_tao_all();
		else
			print_tao(argv[i]);
	}
	return EXIT_SUCCESS;
}
