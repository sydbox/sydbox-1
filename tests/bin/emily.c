/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

struct test {
	const char *name;
	int (*func) (int argc, char **argv);
} test_table[] = {
	{"access",	test_access},
	{"faccessat",	test_faccessat},
	{"stat",	test_stat},
	{"chmod",	test_chmod},
	{"fchmodat",	test_fchmodat},
	{"chown",	test_chown},
	{"lchown",	test_lchown},
	{"fchownat",	test_fchownat},
	{"open",	test_open},
	{"openat",	test_openat},
	{"creat",	test_creat},
	{"mkdir",	test_mkdir},
	{"mkdirat",	test_mkdirat},
	{"mknod",	test_mknod},
	{"mknodat",	test_mknodat},
	{"rename",	test_rename},
	{"renameat",	test_renameat},
	{"rmdir",	test_rmdir},
	{"utimensat",	test_utimensat},
	{NULL,		NULL},
};

static void usage(FILE *outfile, int exitcode)
{
	int i;

	fprintf(outfile, "Usage: emily test [arguments]\n");
	fprintf(outfile, "Available tests:\n");
	for (i = 0; test_table[i].name != NULL; i++)
		fprintf(outfile, "\t%s\n", test_table[i].name);
	exit(exitcode);
}

int main(int argc, char **argv)
{
	int i;
	const char *test_name;

	if (argc < 2)
		usage(stderr, 1);
	test_name = argv[1];
	argc -= 1;
	argv += 1;

	for (i = 0; test_table[i].name; i++) {
		if (!strcmp(test_name, test_table[i].name))
			return test_table[i].func(argc, argv);
	}

	usage(stderr, 127);
}
