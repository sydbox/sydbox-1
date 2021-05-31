/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

static void test_rmdir_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily rmdir [-h] -e errno <file>\n\
\n\
Options:\n\
-h, --help                           -- Show help\n\
-e <errno>, --errno=<errno>          -- Expected errno\n\
\n\
For errno == EFAULT <file> may not be specified.\n\
");
	exit(exitcode);
}

int test_rmdir(int argc, char **argv)
{
	int optc;
	int test_errno = TEST_ERRNO_INVALID;
	const char *test_file;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "he:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_rmdir_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_rmdir_usage(stderr, 2);
			break;
		default:
			test_rmdir_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_rmdir_usage(stderr, 1);

	if (test_errno == EFAULT)
		test_file = NULL;
	else if (argc != 1)
		test_rmdir_usage(stderr, 1);
	else
		test_file = argv[0];

	errno = 0;
	if (rmdir(test_file) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}
