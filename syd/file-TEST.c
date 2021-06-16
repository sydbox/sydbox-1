/*
 * libsyd/proc-TEST.c
 *
 * file and path utility tests
 *
 * Copyright (c) 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#define _GNU_SOURCE 1
#include "check.h"

#include <limits.h>
#include <stdlib.h>

#if AT_FDCWD == -128
#define INVALID_FD -129
#else
#define INVALID_FD -128
#endif

#define TMPDIR			"./file-TEST-tmp"
#define TMP_FILE		"file"
#define TMP_VOID_FILE		"void"
#define TMP_LINK		"link"
#define TMP_DANG_LINK		"dang"
#define TMP_LOOP_LINK		"loop"
#define TMP_LOOP_LOOP_LINK	"loop-loop"
#define TMP_LONG		"long"
#define TMP_LONG_NAME		"3.141592653589793238462643383279502884197169" \
				"39937510582097494459230781640628620899862803" \
				"482534211706798214808651328230664709384"
#define TMP_LONG_MAGIC		32
#define TMP_RMTREE "perl -mFile::Path -e 'File::Path::rmtree(\""TMPDIR"\")'"
static char *tmpdir;
static char *tmp_file;
static char *tmp_void_file;
static char *tmp_link;
static char *tmp_dang_link;
static char *tmp_loop_link;

static int test_cwd_fd;

static void test_setup(void)
{
	assert_int_equal(0, system(TMP_RMTREE));
	assert_int_equal(0, system("mkdir -p -m700 "TMPDIR));
	assert_int_equal(0, system("touch "TMPDIR"/"TMP_FILE));
	assert_int_equal(0, system("ln -s file "TMPDIR"/"TMP_LINK));
	assert_int_equal(0, system("ln -s void "TMPDIR"/"TMP_DANG_LINK));
	assert_int_equal(0, system("ln -s loop "TMPDIR"/"TMP_LOOP_LINK"-loop"));
	assert_int_equal(0, system("ln -s loop-loop "TMPDIR"/"TMP_LOOP_LINK));
	tmpdir = realpath(TMPDIR, NULL);
	assert_true(tmpdir != NULL);
	assert_true(asprintf(&tmp_file, "%s/"TMP_FILE, tmpdir) != -1);
	assert_true(asprintf(&tmp_void_file, "%s/"TMP_VOID_FILE, tmpdir) != -1);
	assert_true(asprintf(&tmp_link, "%s/"TMP_LINK, tmpdir) != -1);
	assert_true(asprintf(&tmp_dang_link, "%s/"TMP_DANG_LINK, tmpdir) != -1);
	assert_true(asprintf(&tmp_loop_link, "%s/"TMP_LOOP_LINK, tmpdir) != -1);

	assert_int_equal(0, system("mkdir -p -m700 "TMPDIR"/"TMP_LONG));
	assert_int_equal(0, chdir(TMPDIR"/"TMP_LONG));
	for (unsigned int i = 0; i < TMP_LONG_MAGIC; i++) {
		assert_int_equal(0, system("mkdir -p -m700 "TMP_LONG_NAME));
		assert_int_equal(0, chdir("./"TMP_LONG_NAME));
	}
	assert_int_equal(0, fchdir(test_cwd_fd));
	;
}

static void test_teardown(void)
{
	assert_int_equal(0, fchdir(test_cwd_fd));
	assert_int_equal(0, system(TMP_RMTREE));
	if (tmpdir)
		free(tmpdir);
	if (tmp_file)
		free(tmp_file);
	if (tmp_void_file)
		free(tmp_void_file);
	if (tmp_link)
		free(tmp_link);
	if (tmp_dang_link)
		free(tmp_dang_link);
	if (tmp_loop_link)
		free(tmp_loop_link);
	tmpdir = NULL;
	tmp_file = NULL;
	tmp_void_file = NULL;
	tmp_link = NULL;
	tmp_dang_link = NULL;
	tmp_loop_link = NULL;
}

static void test_syd_readlink_alloc_01(void)
{
	char *buf;

	assert_int_equal(-EINVAL, syd_readlink_alloc(NULL, &buf));
	assert_int_equal(-EINVAL, syd_readlink_alloc("root", NULL));

	assert_int_equal(sizeof(TMP_FILE), syd_readlink_alloc(tmp_link, &buf));
	assert_true(buf[sizeof(TMP_FILE) - 1] == '\0');
	assert_string_equal(TMP_FILE, buf);
	free(buf); buf = NULL;

	assert_int_equal(sizeof(TMP_VOID_FILE), syd_readlink_alloc(tmp_dang_link, &buf));
	assert_true(buf[sizeof(TMP_VOID_FILE) - 1] == '\0');
	assert_string_equal(TMP_VOID_FILE, buf);
	free(buf); buf = NULL;

	assert_int_equal(sizeof(TMP_LOOP_LOOP_LINK), syd_readlink_alloc(tmp_loop_link, &buf));
	assert_true(buf[sizeof(TMP_LOOP_LOOP_LINK) - 1] == '\0');
	assert_string_equal(TMP_LOOP_LOOP_LINK, buf);
	free(buf);
}

static void test_syd_readlink_alloc_02(void)
{
#if 0
#error TODO: syd_readlink_alloc() is not yet used, this test must be fixed before.
	char *buf;

	assert_int_equal(0, chdir(TMPDIR"/"TMP_LONG));
	for (unsigned int i = 0; i < TMP_LONG_MAGIC; i++)
		assert_int_equal(0, chdir("./"TMP_LONG_NAME));
	assert_int_equal(12, syd_readlink_alloc("/proc/self/cwd", &buf));
	assert_string_equal("foo", buf);
#endif
	;
}

static void test_syd_path_root_check_01(void)
{
	assert_int_equal(-EINVAL, syd_path_root_check(NULL));
	assert_int_equal(-EINVAL, syd_path_root_check("root"));
	assert_int_equal(-ENOENT, syd_path_root_check("/.../"));
	assert_int_equal(-ENOENT, syd_path_root_check("/./.../"));
	assert_int_equal(-ENOENT, syd_path_root_check("/../.../"));
	assert_int_equal(-ENOENT, syd_path_root_check("/..."));
	assert_int_equal(-ENOENT, syd_path_root_check("/./..."));
	assert_int_equal(-ENOENT, syd_path_root_check("/../..."));
	assert_int_equal(0, syd_path_root_check("/"));
	assert_int_equal(0, syd_path_root_check("//"));
	assert_int_equal(0, syd_path_root_check("///"));
	assert_int_equal(0, syd_path_root_check("////"));
	assert_int_equal(0, syd_path_root_check("/./"));
	assert_int_equal(0, syd_path_root_check("/././"));
	assert_int_equal(0, syd_path_root_check("/../"));
	assert_int_equal(0, syd_path_root_check("/.././"));
	assert_int_equal(0, syd_path_root_check("/../../"));
	assert_int_equal(0, syd_path_root_check("/../.././"));
	assert_int_equal(0, syd_path_root_check("/../../../"));
	assert_int_equal(1, syd_path_root_check("//root"));
	assert_int_equal(2, syd_path_root_check("///root"));
	assert_int_equal(3, syd_path_root_check("////root"));
	assert_int_equal(2, syd_path_root_check("/./root"));
	assert_int_equal(4, syd_path_root_check("/././root"));
	assert_int_equal(3, syd_path_root_check("/../root"));
	assert_int_equal(5, syd_path_root_check("/.././root"));
	assert_int_equal(6, syd_path_root_check("/../../root"));
	assert_int_equal(8, syd_path_root_check("/../.././root"));
	assert_int_equal(9, syd_path_root_check("/../../../root"));
}

#if 0
static void test_syd_realpath_at_01(void)
{
	int r;
	char *buf;

	/* 3rd argument is NULL should return -EINVAL" */
	r = syd_realpath_at(1, "/root", NULL, 0);
	assert_int_equal(-EINVAL, r); 

	r = syd_realpath_at(INVALID_FD, NULL, &buf, 0);
	assert_int_equal(-EINVAL, r);
	r = syd_realpath_at(INVALID_FD, NULL, &buf, SYD_REALPATH_EXIST);
	assert_int_equal(-EINVAL, r);
	r = syd_realpath_at(INVALID_FD, NULL, &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(-EINVAL, r);

	r = syd_realpath_at(INVALID_FD, "/", &buf, 0);
	assert_int_equal(-EINVAL, r);

	r = syd_realpath_at(INVALID_FD, "", &buf, 0);
	assert_int_equal(-ENOENT, r);
}

static void test_syd_realpath_at_02(void)
{
	int r;
	char *buf;

	r = syd_realpath_at(0, "/", &buf, 0);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "//", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "//", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "///", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "///", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "////", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "////", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/./", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/./", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/././", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/././", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/.././", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/.././", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../.././", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../.././", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../../", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../../", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);
}

static void test_syd_realpath_at_03(void)
{
	int ne;
	char *r1, *r2;

	r1 = realpath(TMPDIR"//./..//"TMPDIR"/"TMP_FILE, NULL);
	ne = syd_realpath_at(AT_FDCWD, TMPDIR"//./..//"TMPDIR"/"TMP_FILE, &r2,
			     SYD_REALPATH_EXIST);
	assert_true(r1 != NULL);
	assert_int_equal(0, ne);
	assert_string_equal(r1, r2);
	assert_true(strstr(r1, "/"TMPDIR"/"TMP_FILE) ==
		    r1 + strlen(r1) - strlen("/"TMPDIR"/"TMP_FILE));
	free(r1);
	free(r2);
}
#endif

static void test_fixture_file(void)
{
	test_cwd_fd = open(".", O_PATH|O_CLOEXEC|O_DIRECTORY);
	if (test_cwd_fd < 0) {
		perror("file-TEST: open");
		return;
	}
	test_fixture_start();

	fixture_setup(test_setup);
	fixture_teardown(test_teardown);

	run_test(test_syd_readlink_alloc_01);
	run_test(test_syd_readlink_alloc_02);
	run_test(test_syd_path_root_check_01);
#if 0
	run_test(test_syd_realpath_at_01);
	run_test(test_syd_realpath_at_02);
	run_test(test_syd_realpath_at_03);
#endif

	test_fixture_end();
	close(test_cwd_fd);
}

void test_suite_file(void)
{
	test_fixture_file();
}
