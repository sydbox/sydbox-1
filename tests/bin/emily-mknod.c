/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

static void test_mknod_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily mknod [-h] [-m octal-mode] -e errno <file>\n\
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

static void test_mknodat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily mknodat [-hr] [-m <octal-mode>] -d dir -e errno <file>\
\n\
Options:\n\
-h, --help                           -- Show help\n\
-e <errno, --errno=<errno>           -- Expected errno\n\
-m <octal-mode>, --mode=<octal-mode> -- Octal mode\n\
-d <dir>, --dir=<dir>                -- Directory name or 'cwd' or 'null'\n\
\n\
For errno == EFAULT <file> may not be specified.\n\
");
	exit(exitcode);
}

int test_mknod(int argc, char **argv)
{
	int optc;
	int test_errno = TEST_ERRNO_INVALID;
	mode_t test_mode = 0600;
	const char *test_file;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"mode",	required_argument,	NULL,	'm'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "he:m:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_mknod_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_mknod_usage(stderr, 2);
			break;
		case 'm':
			if (!parse_octal(optarg, &test_mode))
				test_mknod_usage(stderr, 2);
			break;
		default:
			test_mknod_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_mknod_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_file = NULL;
	} else if (argc != 1) {
		test_mknod_usage(stderr, 1);
	} else {
		test_file = argv[0];
	}

	errno = 0;
	if (mknod(test_file, S_IFIFO|test_mode, 0) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}

int test_mknodat(int argc, char **argv)
{
	int optc;
	int test_errno = TEST_ERRNO_INVALID;
	int test_dirfd = TEST_DIRFD_INVALID;
	mode_t test_mode = 0000;
	const char *test_file;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"mode",	required_argument,	NULL,	'm'},
		{"dir",		required_argument,	NULL,	'd'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "hd:e:m:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_mknodat_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_mknodat_usage(stderr, 2);
			break;
		case 'm':
			if (!parse_octal(optarg, &test_mode))
				test_mknodat_usage(stderr, 2);
			break;
		case 'd':
			if (streq(optarg, "cwd")) {
				test_dirfd = AT_FDCWD;
			} else if (streq(optarg, "null")) {
				test_dirfd = TEST_DIRFD_NOEXIST; /* EBADF! */
			} else {
				test_dirfd = open(optarg, O_RDONLY|O_DIRECTORY);
				if (test_dirfd < 0) {
					fprintf(stderr, "test_mknodat: open(%s) failed (errno:%d %s)\n",
							optarg, errno, strerror(errno));
					exit(2);
				}
			}
			break;
		default:
			test_mknodat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_mknodat_usage(stderr, 1);
	if (test_dirfd == TEST_DIRFD_INVALID)
		test_mknodat_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_file = NULL;
	} else if (argc != 1) {
		test_mknodat_usage(stderr, 1);
	} else {
		test_file = argv[0];
	}

	errno = 0;
	if (mknodat(test_dirfd, test_file, S_IFIFO|test_mode, 0) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}
