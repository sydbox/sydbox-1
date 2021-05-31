/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

static void test_creat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily creat [-h] [-m octal-mode] -e errno <file>\n\
\n\
Options:\n\
-h, --help                           -- Show help\n\
-e <errno>, --errno=<errno>          -- Expected errno\n\
-m <octal-mode>, --mode=<octal-mode> -- Octal mode\n\
\n\
For errno == EFAULT <file> may not be specified.\n\
");
	exit(exitcode);
}

int test_creat(int argc, char **argv)
{
	int optc;
	int test_fd;
	int test_errno = TEST_ERRNO_INVALID;
	mode_t test_mode = 0600;
	const char *test_file;
	const char *test_data = NULL;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"mode",	required_argument,	NULL,	'm'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "he:m:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_creat_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_creat_usage(stderr, 2);
			break;
		case 'm':
			if (!parse_octal(optarg, &test_mode))
				test_creat_usage(stderr, 2);
			break;
		default:
			test_creat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_creat_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_file = NULL;
	} else if (argc < 1 || argc > 2) {
		test_creat_usage(stderr, 1);
	} else {
		test_file = argv[0];
		if (argc == 2)
			test_data = argv[1];
	}

	errno = 0;
	test_fd = creat(test_file, test_mode);
	if (test_fd < 0)
		return expect_errno(errno, test_errno);
	if (test_data)
		do_write(test_fd, test_data, sizeof(test_data));
	do_close(test_fd);
	return expect_errno(0, test_errno);
}
