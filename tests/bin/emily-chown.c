/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

#define test_chown_usage(f, c)	test_usage_chown_("chown", (f), (c))
#define test_lchown_usage(f, c)	test_usage_chown_("lchown", (f), (c))
static void test_usage_chown_(const char *sysname, FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily %s [-h] -e errno <file>\n\
\n\
Options:\n\
-h, --help                   -- Show help\n\
-e <errno>, --errno=<errno>  -- Expected errno\n\
\n\
For errno == EFAULT <file> may not be specified.\n\
", sysname);
	exit(exitcode);
}

static void test_fchownat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily fchownat [-hn] -d dir -e errno <file>\
\n\
Options:\n\
-h, --help                 -- Show help\n\
-e <errno, --errno=<errno> -- Expected errno\n\
-n, --no-follow            -- Do not follow symbolic links\n\
-d <dir>, --dir=<dir>      -- Directory name or 'cwd' or 'null'\n\
\n\
For errno == EFAULT <file> may not be specified.\n\
");
	exit(exitcode);
}

int test_chown(int argc, char **argv)
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
			test_chown_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_chown_usage(stderr, 2);
			break;
		default:
			test_chown_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_chown_usage(stderr, 1);

	if (test_errno == EFAULT)
		test_file = NULL;
	else if (argc != 1)
		test_chown_usage(stderr, 1);
	else
		test_file = argv[0];

	errno = 0;
	if (chown(test_file, geteuid(), getegid()) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}

int test_lchown(int argc, char **argv)
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
			test_lchown_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_lchown_usage(stderr, 2);
			break;
		default:
			test_lchown_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_lchown_usage(stderr, 1);

	if (test_errno == EFAULT)
		test_file = NULL;
	else if (argc != 1)
		test_lchown_usage(stderr, 1);
	else
		test_file = argv[0];

	errno = 0;
	if (lchown(test_file, geteuid(), getegid()) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}

int test_fchownat(int argc, char **argv)
{
	int optc;
	bool test_nofollow = false;
	int test_errno = TEST_ERRNO_INVALID;
	int test_dirfd = TEST_DIRFD_INVALID;
	const char *test_file;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"no-follow",	no_argument,		NULL,	'n'},
		{"dir",		required_argument,	NULL,	'd'},
		{"errno",	required_argument,	NULL,	'e'},
	};

	while ((optc = getopt_long(argc, argv, "hnd:e:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_fchownat_usage(stdout, 0);
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
					fprintf(stderr, "test_fchownat: open(%s) failed (errno:%d %s)\n",
							optarg, errno, strerror(errno));
					exit(2);
				}
			}
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_fchownat_usage(stderr, 2);
			break;
		default:
			test_fchownat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_fchownat_usage(stderr, 1);
	if (test_dirfd == TEST_DIRFD_INVALID)
		test_fchownat_usage(stderr, 1);

	if (test_errno == EFAULT)
		test_file = NULL;
	else if (argc != 1)
		test_fchownat_usage(stderr, 1);
	else
		test_file = argv[0];

	errno = 0;
	if (fchownat(test_dirfd, test_file,
				geteuid(), getegid(),
				test_nofollow ? AT_SYMLINK_NOFOLLOW : 0) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}
