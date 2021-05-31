/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2012, 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

/* TODO:
 * Make this a global function to use it in other files like emily-chmod.c etc.
 */
static void parse_dir_arg(const char *myoptarg, int *dfd) {
	assert(dfd);

	if (streq(myoptarg, "cwd")) {
		*dfd = AT_FDCWD;
	} else if (streq(myoptarg, "null")) {
		*dfd = TEST_DIRFD_NOEXIST; /* EBADF! */
	} else {
		*dfd = open(myoptarg, O_RDONLY|O_DIRECTORY);
		if (*dfd < 0) {
			fprintf(stderr, "%s:%s(): open(%s) failed (errno:%d %s)\n",
				__FILE__, __func__, myoptarg,
				errno, strerror(errno));
			exit(2);
		}
	}
}

static void test_rename_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily rename [-h] -e errno <oldpath> <newpath>\n\
\n\
Options:\n\
-h, --help                           -- Show help\n\
-e <errno>, --errno=<errno>          -- Expected errno\n\
\n\
For errno == EFAULT <oldpath> and <newpath> may not be specified.\n\
");
	exit(exitcode);
}

static void test_renameat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily renameat [-hn] -f olddir -t newdir -e errno <oldpath> <newpath>\
\n\
Options:\n\
-h, --help                           -- Show help\n\
-e <errno, --errno=<errno>           -- Expected errno\n\
-f <olddir>, --from=<olddir>         -- Directory name or 'cwd' or 'null'\n\
-t <newdir>, --to=<newdir>           -- Directory name or 'cwd' or 'null'\n\
\n\
For errno == EFAULT <oldpath> and <newpath> may not be specified.\n\
");
	exit(exitcode);
}

int test_rename(int argc, char **argv)
{
	int optc;
	int test_errno = TEST_ERRNO_INVALID;
	const char *test_oldpath;
	const char *test_newpath;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "he:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_rename_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_rename_usage(stderr, 2);
			break;
		default:
			test_rename_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_rename_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_oldpath = NULL;
		test_newpath = NULL;
	} else if (argc != 2) {
		test_rename_usage(stderr, 1);
	} else {
		test_oldpath = argv[0];
		test_newpath = argv[1];

	}

	errno = 0;
	if (rename(test_oldpath, test_newpath) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}

int test_renameat(int argc, char **argv)
{
	int optc;
	int test_errno = TEST_ERRNO_INVALID;
	int test_olddirfd = TEST_DIRFD_INVALID;
	int test_newdirfd = TEST_DIRFD_INVALID;
	const char *test_oldpath;
	const char *test_newpath;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"from",	required_argument,	NULL,	'f'},
		{"to",		required_argument,	NULL,	't'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "he:f:t:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_renameat_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_renameat_usage(stderr, 2);
			break;
		case 'f':
			parse_dir_arg(optarg, &test_olddirfd);
			break;
		case 't':
			parse_dir_arg(optarg, &test_newdirfd);
			break;
		default:
			test_renameat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_renameat_usage(stderr, 1);
	if (test_olddirfd == TEST_DIRFD_INVALID)
		test_renameat_usage(stderr, 1);
	if (test_newdirfd == TEST_DIRFD_INVALID)
		test_renameat_usage(stderr, 1);

	if (test_errno == EFAULT) {
		test_oldpath = NULL;
		test_newpath = NULL;
	} else if (argc != 2) {
		test_renameat_usage(stderr, 1);
	} else {
		test_oldpath = argv[0];
		test_newpath = argv[1];
	}

	errno = 0;
	if (renameat(test_olddirfd, test_oldpath,
		     test_newdirfd, test_newpath) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}
