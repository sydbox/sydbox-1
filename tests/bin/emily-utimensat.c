/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2013 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "emily.h"

static void test_utimensat_usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: emily utimensat [-hn] [-t <time_in_seconds>] -d dir -e errno <file>\
\n\
Options:\n\
-h, --help                           -- Show help\n\
-e <errno>, --errno=<errno>          -- Expected errno\n\
-n, --no-follow                      -- Do not follow symbolic links\n\
-t <sec>, --time=<sec>               -- Time in seconds\n\
-d <dir>, --dir=<dir>                -- Directory name or 'cwd' or 'null'\n\
\n\
For errno == EBADF|EFAULT|EINVAL <file> may not be specified.\n\
");
	exit(exitcode);
}

int test_utimensat(int argc, char **argv)
{
	int optc;
	bool test_nofollow = false;
	int test_errno = TEST_ERRNO_INVALID;
	int test_dirfd = TEST_DIRFD_INVALID;
	struct timespec test_times[2] = {
		{.tv_sec = 0, .tv_nsec = 0},
		{.tv_sec = 0, .tv_nsec = 0}
	};
	const char *test_file = NULL;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"errno",	required_argument,	NULL,	'e'},
		{"time",	required_argument,	NULL,	't'},
		{"dir",		required_argument,	NULL,	'd'},
		{"no-follow",	no_argument,		NULL,	'n'},
		{NULL,		0,			NULL,	0},
	};

	while ((optc = getopt_long(argc, argv, "hnd:e:t:", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			test_utimensat_usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				test_utimensat_usage(stderr, 2);
			break;
		case 't':
			test_times[0].tv_sec = test_times[1].tv_sec = atoi(optarg);
			break;
		case 'n':
			test_nofollow = true;
			break;
		case 'd':
			if (streq(optarg, "cwd")) {
				test_dirfd = AT_FDCWD;
				printf("yay!\n");
			} else if (streq(optarg, "null")) {
				test_dirfd = TEST_DIRFD_NOEXIST; /* EBADF! */
			} else {
				test_dirfd = open(optarg, O_RDONLY);
				if (test_dirfd < 0) {
					fprintf(stderr, "test_utimensat: open(%s) failed (errno:%d %s)\n",
							optarg, errno, strerror(errno));
					exit(2);
				}
			}
			break;
		default:
			test_utimensat_usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_errno == TEST_ERRNO_INVALID)
		test_utimensat_usage(stderr, 1);
	if (test_dirfd == TEST_DIRFD_INVALID)
		test_utimensat_usage(stderr, 1);

	if (argc == 0) {
		if (!(test_file == NULL &&
		      (test_errno == EBADF ||
		       test_errno == EFAULT ||
		       test_errno == EINVAL)))
			test_utimensat_usage(stderr, 1);
	} else if (argc != 1) {
		test_utimensat_usage(stderr, 1);
	} else {
		test_file = argv[0];
	}

	errno = 0;
	if (syscall(SYS_utimensat, test_dirfd, test_file, test_times,
		      test_nofollow ? AT_SYMLINK_NOFOLLOW : 0) < 0)
		return expect_errno(errno, test_errno);
	return expect_errno(0, test_errno);
}
