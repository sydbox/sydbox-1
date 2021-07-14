/*
 * libsyd/sha1-TEST.c
 *
 * SHA-1 calculator tests
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "check.h"
#include <libgen.h>
#include <syd/syd.h>

#define SYD_SHA1_SAMPLES_MAX 12
static const char *syd_sha1_samples[SYD_SHA1_SAMPLES_MAX] = {
	"sha1_samples/200d69c3555389e536b57d7f9f95eb1eb5e377a1",
	"sha1_samples/2d34e230014f5dbd4e9b2344d23bf3fce94fae38",
	"sha1_samples/48edf6bfd0c00f87d86fd23d67d0351495e106b1",
	"sha1_samples/50865daa00c7f3f238c774ea13a2f25cbc8ed27a",
	"sha1_samples/5c828d244d745a59ed85bd472bdc6bb4d6ecea89",
	"sha1_samples/89a91d5421249fbd8cb448ebf5d2b42798e3126c",
	"sha1_samples/8dea5576cecc69b043c937e87ce3d035dfbaf971",
	"sha1_samples/953edfc0217c405b17f647dbd749d4b09ce8aa49",
	"sha1_samples/a3e2cc1f7e2e2659b8080a6ec3534c322551f834",
	"sha1_samples/c325d19b0aa730530c849805a4ce5a5da5bb25d1",
	"sha1_samples/c8b8d277235110eea01a836b6e9ab9e66d48c90d",
	"sha1_samples/e2a01a5166873953413b502c2fd75620b751e4e8",
};

static void test_setup(void)
{
	;
}

static void test_teardown(void)
{
	;
}

static void test_sha1_partialcoll(void)
{
	int r;
	char hex[SYD_SHA1_HEXSZ+1] = {0};

	for (uint8_t i = 0; i < SYD_SHA1_SAMPLES_MAX; i++) {
		char *path = syd_sha1_samples[i];
		if ((r = syd_path_to_sha1_hex(path, hex)) < 0)
			fail_msg("syd_path_to_sha1(»%s«) failed (errno:%d %s)",
				 path, errno, strerror(errno));
		/* Basename is the correct SHA1 check sum. */
		char *name = basename(path);
		if (strcasecmp(name, hex))
			fail_msg("SHA-1 Hash Mismatch for Sample %d, expected »%s«, got »%s«.",
				 i + 1, name, hex);
	}
}

static void test_fixture_sha1(void)
{
	test_fixture_start();

	fixture_setup(test_setup);
	fixture_teardown(test_teardown);

	run_test(test_sha1_partialcoll);

	test_fixture_end();
}

void test_suite_sha1(void)
{
	test_fixture_sha1();
}
