/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

static bool set_open_mode(const char *s, int *flags)
{
	assert(flags);

	if (streq(s, "rdonly"))
		*flags |= O_RDONLY;
	else if (streq(s, "wronly"))
		*flags |= O_WRONLY;
	else if (streq(s, "rdwr"))
		*flags |= O_RDWR;
	else
		return false;
	return true;
}

static void test_open_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily open [-hcx] -e errno -m mode <file> <data-to-write>\n\
\n\
Options:\n\
-h, --help                   -- Show help\n\
-e <errno>, --errno=<errno>  -- Expected errno\n\
-m <mode>, --mode=<mode>     -- One of 'rdonly', 'wronly' or 'rdwr'\n\
-c, --creat                  -- Specify O_CREAT in flags\n\
-x, --excl                   -- Specify O_EXCL in flags\n\
-D, --directory              -- Specify O_DIRECTORY in flags\n\
-F, --no-follow              -- Specify O_NOFOLLOW in flags\n\
\n\
<data-to-write> must be specified for 'wronly' and 'rdwr' modes only.\n\
For errno == EFAULT <mode>, <file> and <data-to-write> may not be specified.\n\
");
	exit(exitcode);
}

static void test_openat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily openat [-hcx] -e errno -m mode -d dir <file> <data-to-write>\n\
\n\
Options:\n\
-h, --help                 -- Show help\n\
-e <errno, --errno=<errno> -- Expected errno\n\
-m <mode>, --mode=<mode>   -- One of 'rdonly', 'wronly' or 'rdwr'\n\
-c, --creat                -- Specify O_CREAT in flags\n\
-x, --excl                 -- Specify O_EXCL in flags\n\
-D, --directory            -- Specify O_DIRECTORY in flags\n\
-F, --no-follow            -- Specify O_NOFOLLOW in flags\n\
-d <dir>, --dir=<dir>      -- Directory name or 'cwd' or 'null'\n\
\n\
<data-to-write> must be specified for 'wronly' and 'rdwr' modes only.\n\
For errno == EFAULT <mode>, <file> and <data-to-write> may not be specified.\n\
");
	exit(exitcode);
}

int test_open(int argc, char **argv)
{
	int optc;
	bool seen_mode = false;
	int test_fd;
	int test_errno = TEST_ERRNO_INVALID;
	int test_flags = 0;
	const char *test_file;
	const char *test_data = NULL;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"creat",	no_argument,		NULL,	'c'},
		{"excl",	no_argument,		NULL,	'x'},
		{"directory",	no_argument,		NULL,	'D'},
		{"no-follow",	no_argument,		NULL,	'F'},
		{"errno",	required_argument,	NULL,	'e'},
		{"mode",	required_argument,	NULL,	'm'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "hcxDFe:m:", long_options,
				   NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_open_usage(stdout, 0);
			break;
		case 'c':
			test_flags |= O_CREAT;
			break;
		case 'x':
			test_flags |= O_EXCL;
			break;
		case 'D':
			test_flags |= O_DIRECTORY;
			break;
		case 'F':
			test_flags |= O_NOFOLLOW;
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_open_usage(stderr, 2);
			break;
		case 'm':
			if (!set_open_mode(optarg, &test_flags))
				test_open_usage(stderr, 2);
			seen_mode = true;
			break;
		default:
			test_open_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_open_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_file = NULL;
		test_flags = 0;
	} else if (argc < 1 || argc > 2) {
		test_open_usage(stderr, 1);
	} else {
		if (!seen_mode)
			test_open_usage(stderr, 2);
		test_file = argv[0];
		if (argc == 2)
			test_data = argv[1];
	}

	errno = 0;
	test_fd = open(test_file, test_flags);
	if (test_fd < 0)
		return expect_errno(errno, test_errno);
	if (test_data)
		do_write(test_fd, test_data, sizeof(test_data));
	do_close(test_fd);
	return expect_errno(0, test_errno);
}

int test_openat(int argc, char **argv)
{
	int optc;
	bool seen_mode = false;
	int test_fd;
	int test_errno = TEST_ERRNO_INVALID;
	int test_dirfd = TEST_DIRFD_INVALID;
	int test_flags = 0;
	const char *test_file;
	const char *test_data = NULL;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"creat",	no_argument,		NULL,	'c'},
		{"excl",	no_argument,		NULL,	'x'},
		{"directory",	no_argument,		NULL,	'D'},
		{"no-follow",	no_argument,		NULL,	'F'},
		{"dir",		required_argument,	NULL,	'd'},
		{"errno",	required_argument,	NULL,	'e'},
		{"mode",	required_argument,	NULL,	'm'},
	};

	while ((optc = getopt_long(argc, argv, "hcxDFd:e:m:", long_options,
				   NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_openat_usage(stdout, 0);
			break;
		case 'c':
			test_flags |= O_CREAT;
			break;
		case 'x':
			test_flags |= O_EXCL;
			break;
		case 'D':
			test_flags |= O_DIRECTORY;
			break;
		case 'F':
			test_flags |= O_NOFOLLOW;
			break;
		case 'd':
			if (streq(optarg, "cwd")) {
				test_dirfd = AT_FDCWD;
			} else if (streq(optarg, "null")) {
				test_dirfd = TEST_DIRFD_NOEXIST; /* EBADF! */
			} else {
				test_dirfd = open(optarg, O_RDONLY|O_DIRECTORY);
				if (test_dirfd < 0) {
					fprintf(stderr, "test_openat: open(%s) failed (errno:%d %s)\n",
							optarg, errno, strerror(errno));
					exit(2);
				}
			}
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_openat_usage(stderr, 2);
			break;
		case 'm':
			if (!set_open_mode(optarg, &test_flags))
				test_openat_usage(stderr, 2);
			seen_mode = true;
			break;
		default:
			test_openat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_openat_usage(stderr, 1);
	if (test_dirfd == TEST_DIRFD_INVALID)
		test_openat_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_flags = 0;
		test_file = NULL;
	} else if (argc < 1 || argc > 2) {
		test_openat_usage(stderr, 1);
	} else {
		if (!seen_mode)
			test_openat_usage(stderr, 2);
		test_file = argv[0];
		if (argc == 2)
			test_data = argv[1];
	}

	errno = 0;
	test_fd = openat(test_dirfd, test_file, test_flags);
	if (test_fd < 0)
		return expect_errno(errno, test_errno);
	if (test_data)
		do_write(test_fd, test_data, sizeof(test_data));
	do_close(test_fd);
	return expect_errno(0, test_errno);
}
