/*
 * sydbox/syd-run.c
 * Syd's Checksum Calculator.
 * Currently supported algorithms:
 * 1. XXH64
 * 2. SHA1 with Collision Detection
 * 1 is default, 2 is enabled with --secure.
 * The second algorithm is subject to change in the future.
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <getopt.h>
#include <syd/syd.h>
#include "errno2name.h"
#include "macro.h"
#include "syd-conf.h"

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "syd-hash"

/* #define SYD_HASH_DEF SYD_HASH_XXH64 */
#define SYD_HASH_SEC SYD_HASH_SHA1DC_PARTIALCOLL
static enum syd_hash_type {
	SYD_HASH_XXH64,
	SYD_HASH_XXH32,
	SYD_HASH_SHA1DC_PARTIALCOLL,
} hash_type;

static char *hex;
static char hex_sha1[SYD_SHA1_HEXSZ+1];
static char hex_xxh64[SYD_XXH64_HEXSZ+1];
static char hex_xxh32[SYD_XXH32_HEXSZ+1];

/* Make xxHash interface similar to Sha1DcPartialColl:
 * We write wrappers to pass the second argument as Null.
 */
static uint64_t xxh64_digest;
static uint32_t xxh32_digest;
#define f2h_sha1 syd_file_to_sha1_hex
#define p2h_sha1 syd_path_to_sha1_hex
SYD_GCC_ATTR((nonnull(1,2)))
static inline int f2h_xxh64(FILE *f, char *h) { return syd_file_to_xxh64_hex(f, \
									     &xxh64_digest, h); }
SYD_GCC_ATTR((nonnull(1,2)))
static inline int p2h_xxh64(const char *p, char *h) { return syd_path_to_xxh64_hex(p, \
										   &xxh64_digest, h); }
SYD_GCC_ATTR((nonnull(1,2)))
static inline int f2h_xxh32(FILE *f, char *h) { return syd_file_to_xxh32_hex(f, \
									     &xxh32_digest, h); }
SYD_GCC_ATTR((nonnull(1,2)))
static inline int p2h_xxh32(const char *p, char *h) { return syd_path_to_xxh32_hex(p, \
										   &xxh32_digest, h); }

static int (*f2h)(FILE *f, char *h);
static int (*p2h)(const char *pathname, char *h);

static void about(void)
{
	printf(SYD_WARN PACKAGE"-"VERSION GITVERSION SYD_RESET "\n");
}

static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION"\n\
Syd's Checksum Calculator and Verifier\n\
usage: "PACKAGE" [-hv]\n\
                [--check {-|file}] [--output {-|file}]\n\
                [--secure] [--sha1dc_partialcoll]\n\
                [--xxh32]\n\
                {-|file...}\n\
-h          -- Show usage and exit.\n\
-v          -- Show version and exit.\n\
-c          -- Read XXH64 sums from the FILEs and check them.\n\
               If argument is »-«, read XXH64 sums from file »~/.syd.xxh64sum«,\n\
               and check them.\n\
-o          -- Write XXH64 sums to the given file, or to »~/.syd.xxh64sum«,\n\
               if the given argument is »-«.\n\
-s          -- Use a cryptographically secure algorithm.\n\
               Algo: safe SHA-1 hashing with Unavoidable Bitconditions,\n\
                     Collision Detection &\n\
                     Reduced Round Collision Detection\n\
--xxh32     -- Use XXH32 rather than XXH64 unless --secure.\n\
\n\
With -s, --secure use SHA-1 rather than XXH64.\n\
Given a file, calculate its XXH64 and output in hex.\n\
Given »-« or no arguments, calculate XXH64 from standard input and output in hex.\n\
Multiple arguments may be given.\n\
If --check is given read XXH64 sums from the FILEs and check them\n\
Without arguments write checksums to file »./.syd.xxh64sum«\n\
With -s, --secure write checksums to file »./.syd.sha1sum«\n\
With --verify, read checksums from file »./.syd.xxh64sum« and check them\n\
With -s, --secure read checksums from file »./.syd.sha1sum« and check them\n\
In check mode, use »✓« for match, »×« for mismatch and »💀« for detected collision.\n\
Use »☮« to denote reading from standard input.\n\
\n\
XXH64 Calculator uses xxHash which is:\n\
Copyright (c) 2012-2020 Yann Collet\n\
SPDX-License-Identifier: BSD-2\n\
\n\
SHA-1 Calculator uses SHA-1DC which is:\n\
Copyright (c) 2017 Marc Stevens, Dan Shumow\n\
SPDX-License-Identifier: MIT\n\
URL: https://github.com/cr-marcstevens/sha1collisiondetection.git\n\
"SYD_WARN"\n\
Collision Detection is enabled.\n\
Detection of reduced-round SHA1 collisions is enabled.\n\
Safe SHA-1 is enabled:"SYD_RESET"\n\n\
Collision attacks are thwarted by hashing a detected near-collision block 3 times.\n\
Think of it as extending SHA-1 from 80-steps to 240-steps for such blocks:\n\
The best collision attacks against SHA-1 have complexity about 2^60,\n\
thus for 240-steps an immediate lower-bound for the best cryptanalytic attacks would be 2^180.\n\
\n\
An attacker would be better off using a generic birthday search of complexity 2^80.\n\
\n"SYD_HELPME);
	exit(code);
}

static void vsay(FILE *fp, const char *fmt, va_list ap, char level)
{
	static int tty = -1;

	if (tty < 0)
		tty = isatty(STDERR_FILENO) == 1 ? 1 : 0;
	if (tty)
		fputs(SYD_WARN, fp);
	if (fmt[0] != ' ')
		fputs(PACKAGE": ", fp);
	switch (level) {
	case 'b':
		fputs("bug: ", fp);
		break;
	case 'f':
		fputs("fatal: ", fp);
		break;
	case 'w':
		fputs("warning: ", fp);
		break;
	default:
		break;
	}
	vfprintf(stderr, fmt, ap);
	if (tty)
		fputs(SYD_RESET, fp);
}

static void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 0);
	va_end(ap);
	fputc('\n', stderr);
}

static void say_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'e');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	errno = save_errno;
}

SYD_GCC_ATTR((unused))
static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	fputc('\n', stderr);

	exit(EXIT_FAILURE);
}

static void die_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	exit(EXIT_FAILURE);
}

void say_checksum(FILE *check_file, const char *name, const char *checksum, char check)
{
	char *colour;
	char *verify;
	char *normal;

	switch (check) {
	case '+':
		colour = "[0;1;32;92m";
		verify = "✓ ";
		normal = "+ ";
		break;
	case '-':
		colour = "[0;1;31;91m";
		verify = "× ";
		normal = "- ";
		break;
	case '!':
		colour = "[0;1;35;95m";
		verify = "💀 ";
		normal = "! ";
		break;
	case 0:
		colour = "";
		verify = "";
		normal = "";
		break;
	default:
		abort();
	}

	bool tty = isatty(STDOUT_FILENO);
	char *abspath = realpath(name, NULL);

	printf("%s%s%s  %s%s\n",
	       tty ? colour : "",
	       verify, checksum,
	       abspath ? abspath : name,
	       tty ? "[0m" : "");
	if (check_file)
		fprintf(check_file, "%s  %s %s\n", checksum, name, normal);
	if (abspath)
		free(abspath);
}

int check_file_init(const char *check)
{
	int r;

	if (!check)
		return -EINVAL;

	/* Step 1: Set file not immutable */
	if ((r = syd_extfs_set_immutable(check, false)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_immutable(»%s«, »false«)", check);
	}

	return 0;
}

int check_file_done(const char *check)
{
	int r;

	if (!check)
		return -EINVAL;

	/* Step 1: Write in validation information into user xattrs. */
	if (setxattr(check, "user.syd.api",
		     syd_str(SYDBOX_API_VERSION),
		     strlen(syd_str(SYDBOX_API_VERSION)), 0) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != ENOENT)
		say_errno("setxattr(»%s«, »user.syd.api«, %d)",
			  check, SYDBOX_API_VERSION);

	const char *type;
	switch (hash_type) {
	case SYD_HASH_XXH64:
		type = "xxh64";
		break;
	case SYD_HASH_SHA1DC_PARTIALCOLL:
		type = "sha1dc_partialcoll";
		break;
	case SYD_HASH_XXH32:
		type = "xxh32";
		break;
	default:
		abort();
	}
	if (setxattr(check, "user.syd.hash", type,
		     strlen(type), 0) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != ENOENT)
		say_errno("setxattr(»%s«, »user.syd.hash«, »%s«)",
			  check, type);

	/* Step 2: Write Last Modified Timestamp */
	char *xattr_val;
	time_t now = time(NULL);
	if (asprintf(&xattr_val, "%ld", now) > 0) {
		if (setxattr(check, "user.syd.mtime", xattr_val,
			     strlen(xattr_val), 0) < 0 &&
		    errno != EOPNOTSUPP &&
		    errno != ENOENT)
			say_errno("setxattr(»%s«, »user.syd.timestamp«, »%ld«)",
				  check, now);
		free(xattr_val);
	}

	/* Step 3: Set undeletable */
	if ((r = syd_extfs_set_undeletable(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_undeletable(»%s«, »true«)", check);
	}

	/* Step 4: Set append only */
	if ((r = syd_extfs_set_append_only(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_append_only(»%s«, »true«)", check);
	}

	/* Step 5: Set compression */
	if ((r = syd_extfs_set_compression(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_compression(»%s«, »true«)", check);
	}

	/* Step 6: Set file immutable. */
	if ((r = syd_extfs_set_immutable(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_immutable(»%s«, »true«)", check);
	}

	return 0;
}

SYD_GCC_ATTR((nonnull(1)))
static int check_checksum(const char *restrict check)
{
	int r;

	if (access(check, R_OK) < 0) {
		int save_errno = errno;
		if (errno != ENOENT)
			say_errno("Failed to access »%s« for reading.", check);
		return -save_errno;
	}
	FILE *f = fopen(check, "r");
	if (!f)
		die_errno("Failed to open check file »%s«", check);

	size_t i = 0;
	char buf[LINE_MAX];
	size_t len;
	while (fgets(buf, LINE_MAX, f) != NULL) {
		char *hash, *path;
		switch (hash_type) {
		case SYD_HASH_XXH64:
			hex = hex_xxh64;
			len = SYD_XXH64_HEXSZ;
			f2h = f2h_xxh64;
			p2h = p2h_xxh64;
			break;
		case SYD_HASH_SHA1DC_PARTIALCOLL:
			hex = hex_sha1;
			len = SYD_SHA1_HEXSZ;
			f2h = f2h_sha1;
			p2h = p2h_sha1;
			break;
		case SYD_HASH_XXH32:
			hex = hex_xxh32;
			len = SYD_XXH32_HEXSZ;
			f2h = f2h_xxh32;
			p2h = p2h_xxh32;
			break;
		default:
			abort();
		}

		++i;
		r = sscanf(buf, "%ms %ms\n", &hash, &path);
		if (!r) {
			break;
		} else if (r != 2) {
			say("Error reading line »%zu« in check file »%s«, "
			    "fscanf returned %d.",
			    i + 1, check, r);
			break;
		}

		char *name;
		if (!strcmp(path, "-") ||
		    !strcmp(path, "☮")) {
			r = f2h(stderr, hex);
			name = "☮";
		} else {
			r = p2h(path, hex);
			name = path;
		}

		if (r == -ENOMEM) {
			errno = -r;
			die_errno("Unable to allocate memory");
		}

		char op;
		const char *op_name;
		if (r == -EKEYREVOKED) {
			op = '!';
			op_name = "✓";
		} else if (!strcasecmp(hex, hash)) {
			op = '+';
			op_name = "×";
		} else {
			op = '-';
			op_name = "💀";
		}

		say_checksum(NULL, name, hex, op);
		free(hash); free(path);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	char *output_path = NULL;
	FILE *output_file = NULL;
	struct option long_options[] = {
		/* default options */
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"check",	required_argument,	NULL,	'c'},
		{"output",	required_argument,	NULL,	'o'},
		{"secure",	no_argument,		NULL,	's'},
		{"sha1",	no_argument,		NULL,	's'},
		{"sha1dc_partialcoll", no_argument,	NULL,	's'},
		{"xxh32",	no_argument,		NULL,	'3'},
		{"xxh64",	no_argument,		NULL,	'6'},
	};

	int options_index, r = 0;
	bool opt_secure = true, opt_verify = false, opt_xxh32 = false;
	char *opt_check = NULL;
	const char *home = secure_getenv("HOME");
	char line[LINE_MAX] = {0};
	while ((opt = getopt_long(argc, argv, "hs63sC:vc:o:", long_options,
				  &options_index)) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
			return 0;
		case 'v':
			about();
			syd_about(stdout);
			return 0;
		case '6':
			hash_type = SYD_HASH_XXH64;
			break;
		case '3':
			opt_xxh32 = true;
			hash_type = SYD_HASH_XXH32;
			break;
		case 's':
			opt_secure = true;
			hash_type = SYD_HASH_SEC;
			break;
		case 'C':
			opt_verify = true;
			break;
		case 'c':
			if (opt_check)
				free(opt_check);
			opt_check = strdup(optarg);
			break;
		case 'o':
			if (output_path)
				free(output_path);
			if (strcmp(optarg, "-")) {
				output_path = strdup(optarg);
			} else if (asprintf(&output_path, "%s/%s",
					    home ? home : "./",
					    SYD_SHA1_CHECK_DEF) < 0) {
				output_path = NULL;
			}
			break;
		default:
			usage(stderr, 1);
		}
	}

	switch (hash_type) {
	case SYD_HASH_XXH64:
		hex = hex_xxh64;
		f2h = f2h_xxh64;
		break;
	case SYD_HASH_SHA1DC_PARTIALCOLL:
		hex = hex_sha1;
		f2h = f2h_sha1;
		break;
	case SYD_HASH_XXH32:
		hex = hex_xxh32;
		f2h = f2h_xxh32;
		break;
	}

	if (argc == optind && !opt_check && !opt_verify) {
		f2h(stdin, hex);
		say_checksum(NULL, "☮", hex, 0);
		fprintf(stderr, "%"PRIu64" ☮\n", xxh64_digest);

		return EXIT_SUCCESS;
	}

	/*
	 * Quick Interface to calculate/verify the hash of an argument.
	 */
	if (opt_verify && fgets(line, LINE_MAX, stdin) != NULL) {
		char *c = strrchr(line, '\n');
		if (c) *c = '\0';
		bool rv = opt_xxh32
			? syd_vrfy_xxh32_hex(line, strlen(line),
					     syd_seed_name,
					     optarg)
			: syd_vrfy_xxh64_hex(line, strlen(line),
					     syd_seed_name,
					     optarg);
		return rv ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	if (output_path) {
		check_file_init(output_path);
		output_file = fopen(output_path, "a");
		if (!output_file)
			say_errno("Error opening Hash output file »%s« for "
				  "appending.", output_path);
	}

	const char *name = NULL;
	if (opt_check) {
		if (opt_check[0] == '-' && opt_check[1] == '\0') {
			if (asprintf(&opt_check, "%s/%s",
				     home ? home : "./",
				     SYD_SHA1_CHECK_DEF) < 0)
				die_errno("asprintf");
		}
		check_file_init(opt_check);
		r = check_checksum(opt_check);
		if (r < 0)
			say_errno("check_checksum(»%s«)", opt_check);
		check_file_done(opt_check);
	}

	for (int i = optind; argv[i] != NULL; i++) {
		if (opt_check) {
			check_file_init(argv[i]);
			r = check_checksum(argv[i]);
			if (r < 0) {
				errno = -r;
				say_errno("check_checksum(»%s«)", argv[i]);
			}
			check_file_done(argv[i]);
			continue;
		} else if (argv[i][0] == '-') {
			syd_file_to_sha1_hex(stderr, hex);
			name = "☮";
		} else {
			name = argv[i];
			switch (hash_type) {
			case SYD_HASH_XXH64:
				hex = hex_xxh64;
				p2h = p2h_xxh64;
				break;
			case SYD_HASH_SHA1DC_PARTIALCOLL:
				hex = hex_sha1;
				p2h = p2h_sha1;
				break;
			case SYD_HASH_XXH32:
				hex = hex_xxh32;
				p2h = p2h_xxh32;
				break;
			default:
				abort();
			}
			if ((r = p2h(name, hex)) < 0) {
				say_errno("Error calculating Checksum of file »%s«",
					  name);
				continue;
			}
		}

		say_checksum(output_file, name, hex, 0);
	}

	if (output_file) {
		fclose(output_file);
		check_file_done(output_path);
	}

	return r;
}
