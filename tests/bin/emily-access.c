/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

static void test_access_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily access [-h] -e errno -rwx <file>\n\
\n\
Options:\n\
-h, --help                  -- Show help\n\
-e <errno>, --errno=<errno> -- Expected errno\n\
-r, --read                  -- Specify R_OK in flags\n\
-w, --write                 -- Specify W_OK in flags\n\
-x, --execute               -- Specify X_OK in flags\n\
\n\
For errno == EFAULT -rwx flags and <file> may not be specified.\n\
");
	exit(exitcode);
}

static void test_faccessat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily faccessat [-hn] -d dir -e errno -rwx <file>\
\n\
Options:\n\
-h, --help                  -- Show help\n\
-e <errno, --errno=<errno>  -- Expected errno\n\
-n, --no-follow             -- Do not follow symbolic links\n\
-d <dir>, --dir=<dir>       -- Directory name or 'cwd' or 'null'\n\
-r, --read                  -- Specify R_OK in flags\n\
-w, --write                 -- Specify W_OK in flags\n\
-x, --execute               -- Specify X_OK in flags\n\
\n\
For errno == EFAULT -rwx flags and <file> may not be specified.\n\
");
	exit(exitcode);
}

int test_access(int argc, char **argv)
{
	int optc;
	int test_errno = TEST_ERRNO_INVALID;
	int test_mode = -1;
	const char *test_file;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"read",	no_argument,		NULL,	'r'},
		{"write",	no_argument,		NULL,	'w'},
		{"execute",	no_argument,		NULL,	'x'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "he:rwx", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_access_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_access_usage(stderr, 2);
			break;
		case 'r':
			if (test_mode == -1)
				test_mode = R_OK;
			else
				test_mode |= R_OK;
			break;
		case 'w':
			if (test_mode == -1)
				test_mode = W_OK;
			else
				test_mode |= W_OK;
			break;
		case 'x':
			if (test_mode == -1)
				test_mode = X_OK;
			else
				test_mode |= X_OK;
			break;
		default:
			test_access_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_access_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_mode = 0;
		test_file = NULL;
	} else if (argc != 1) {
		test_access_usage(stderr, 1);
	} else {
		if (test_mode == -1)
			test_access_usage(stderr, 2);
		test_file = argv[0];
	}

	printf("test_file:%s test_mode:%d\n", test_file, test_mode);
	errno = 0;
	if (access(test_file, test_mode) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}

int test_faccessat(int argc, char **argv)
{
	int optc;
	bool test_nofollow = false;
	int test_errno = TEST_ERRNO_INVALID;
	int test_dirfd = TEST_DIRFD_INVALID;
	int test_mode = -1;
	const char *test_file;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"read",	no_argument,		NULL,	'r'},
		{"write",	no_argument,		NULL,	'w'},
		{"execute",	no_argument,		NULL,	'x'},
		{"no-follow",	no_argument,		NULL,	'n'},
		{"dir",		required_argument,	NULL,	'd'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "hnd:e:rwx", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_faccessat_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_faccessat_usage(stderr, 2);
			break;
		case 'r':
			if (test_mode == -1)
				test_mode = R_OK;
			else
				test_mode |= R_OK;
			break;
		case 'w':
			if (test_mode == -1)
				test_mode = W_OK;
			else
				test_mode |= W_OK;
			break;
		case 'x':
			if (test_mode == -1)
				test_mode = X_OK;
			else
				test_mode |= X_OK;
			break;
		case 'n':
			test_nofollow = true;
			break;
		case 'd':
			if (streq(optarg, "cwd")) {
				test_dirfd = AT_FDCWD;
			} else if (streq(optarg, "null")) {
				test_dirfd = TEST_DIRFD_NOEXIST; /* EBADF! */
			} else {
				test_dirfd = open(optarg, O_RDONLY|O_DIRECTORY);
				if (test_dirfd < 0) {
					fprintf(stderr, "test_faccessat: open(%s) failed (errno:%d %s)\n",
							optarg, errno, strerror(errno));
					exit(2);
				}
			}
			break;
		default:
			test_faccessat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_faccessat_usage(stderr, 1);
	if (test_dirfd == TEST_DIRFD_INVALID)
		test_faccessat_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_mode = 0;
		test_file = NULL;
	} else if (argc != 1) {
		test_faccessat_usage(stderr, 1);
	} else {
		if (test_mode == -1)
			test_faccessat_usage(stderr, 2);
		test_file = argv[0];
	}

	/* XXX AT_SYMLINK_NOFOLLOW is not implemented! */
	errno = 0;
	if (faccessat(test_dirfd, test_file, test_mode, test_nofollow ? AT_SYMLINK_NOFOLLOW : 0) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}
