/*
 * Test suite for the wildmatch code.
 *
 * Copyright (C) 2003-2009 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

/*
 * Modified by Ali Polatel <alip@exherbo.org>
 * - Use getopt_long() instead of popt
 * - Set output_iterations to 1
 * - Exit non-zero in case of errors, `exit_code' in main()
 * - Use TAP protocol!
 * - Get rid of unused-but-set-parameter
 */

/*#define COMPARE_WITH_FNMATCH*/

/*
#define WILD_TEST_ITERATIONS
#include "lib/wildmatch.c"
*/

#include <limits.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tap.h"

#ifndef MAXPATHLEN
#ifdef PATH_MAX
#define MAXPATHLEN PATH_MAX
#else
#define MAXPATHLEN 1024
#endif
#endif

#ifdef COMPARE_WITH_FNMATCH
#include <fnmatch.h>

int fnmatch_errors = 0;
#endif

int wildmatch_errors = 0;
char number_separator = ',';

/* typedef char bool; */
#include <stdbool.h>

int output_iterations = 1;
int explode_mod = 0;
int empties_mod = 0;
int empty_at_start = 0;
int empty_at_end = 0;

#if 0
static struct poptOption long_options[] = {
  /* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
  {"iterations",     'i', POPT_ARG_NONE,   &output_iterations, 0, 0, 0},
  {"empties",        'e', POPT_ARG_STRING, 0, 'e', 0, 0},
  {"explode",        'x', POPT_ARG_INT,    &explode_mod, 0, 0, 0},
  {0,0,0,0, 0, 0, 0}
};
#endif

static struct option long_options[] = {
	{"iterations",	no_argument,		0, 'i'},
	{"empties",	required_argument,	0, 'e'},
	{"explode",	required_argument,	0, 'x'},
	{NULL,		0,			0,  0},
};

/* match just at the start of string (anchored tests) */
static void
run_test(int line, bool matches, bool same_as_fnmatch,
	 const char *text, const char *pattern)
{
    bool ok = true;
    bool matched;
#ifdef COMPARE_WITH_FNMATCH
    bool fn_matched;
    int flags = strstr(pattern, "**")? 0 : FNM_PATHNAME;
#else
    (void)same_as_fnmatch; /* Get rid of unused-variable compiler warning. */
#endif

    if (explode_mod) {
	char buf[MAXPATHLEN*2], *texts[MAXPATHLEN];
	int pos = 0, cnt = 0, ndx = 0, len = strlen(text);

	if (empty_at_start)
	    texts[ndx++] = "";
	/* An empty string must turn into at least one empty array item. */
	while (1) {
	    texts[ndx] = buf + ndx * (explode_mod + 1);
	    strncpy(texts[ndx++], text + pos, explode_mod + 1);
	    if (pos + explode_mod >= len)
		break;
	    pos += explode_mod;
	    if (!(++cnt % empties_mod))
		texts[ndx++] = "";
	}
	if (empty_at_end)
	    texts[ndx++] = "";
	texts[ndx] = NULL;
	matched = wildmatch_array(pattern, (const char**)texts, 0);
    } else
	matched = wildmatch(pattern, text);
#ifdef COMPARE_WITH_FNMATCH
    fn_matched = !fnmatch(pattern, text, flags);
#endif
    if (matched != matches) {
	tap_not_ok("wildmatch failure on line %d:\n#  %s\n#  %s\n#  expected %s match",
	       line, text, pattern, matches? "a" : "NO");
	wildmatch_errors++;
	ok = false;
    }
#ifdef COMPARE_WITH_FNMATCH
    if (fn_matched != (matches ^ !same_as_fnmatch)) {
	tap_not_ok("fnmatch disagreement on line %d:\n#  %s\n#  %s\n#  expected %s match",
	       line, text, pattern, matches ^ !same_as_fnmatch? "a" : "NO");
	fnmatch_errors++;
	ok = false;
    }
#endif
    if (output_iterations) {
	tap_comment("%d: \"%s\" iterations = %d", line, pattern,
	       wildmatch_iteration_count);
    }
    if (ok) {
	tap_ok("wildmatch ok on line %d:\n#  %s\n#  %s",
	       line, text, pattern);
    }
}

int
main(int argc, char **argv)
{
    char buf[2048], *s, *string[2], *end[2];
    FILE *fp;
    int opt, line, i, flag[2];
    int option_index = 0;
    int exit_code = EXIT_SUCCESS;
    int save_errno;

    while ((opt = getopt_long(argc, argv, "ie:x:", long_options, &option_index)) != EOF) {
	switch(opt) {
	case 'i':
		output_iterations = 1;
		break;
	case 'x':
		explode_mod = atoi(optarg);
		break;
	case 'e':
		empties_mod = atoi(optarg);
		if (strchr(optarg, 's'))
			empty_at_start = 1;
		if (strchr(optarg, 'e'))
			empty_at_end = 1;
		if (!explode_mod)
			explode_mod = 1024;
		break;
	default:
		exit(1);
	}
    }

    argc -= optind;
    argv += optind;

    if (explode_mod && !empties_mod)
	empties_mod = 1024;

    if (argc != 1) {
	tap_plan("wildmatch");
	tap_xbail_out("usage: wildtest [OPTIONS] TESTFILE");
    }

    if ((fp = fopen(argv[0], "r")) == NULL) {
	save_errno = errno;
	tap_plan("wildmatch");
	tap_xbail_out("unable to open `%s' (errno:%d %s)", argv[0],
		      save_errno, strerror(save_errno));
    }

    line = 0;
    while (fgets(buf, sizeof buf, fp)) {
	line++;
	if (*buf == '#' || *buf == '\n')
	    continue;
	for (s = buf, i = 0; i <= 1; i++) {
	    if (*s == '1')
		flag[i] = 1;
	    else if (*s == '0')
		flag[i] = 0;
	    else
		flag[i] = -1;
	    if (*++s != ' ' && *s != '\t')
		flag[i] = -1;
	    if (flag[i] < 0) {
		tap_plan("wildmatch");
		tap_xbail_out("Invalid flag syntax on line %d of %s:\n# %s",
			      line, *argv, buf);
	    }
	    while (*++s == ' ' || *s == '\t') {}
	}
	for (i = 0; i <= 1; i++) {
	    if (*s == '\'' || *s == '"' || *s == '`') {
		char quote = *s++;
		string[i] = s;
		while (*s && *s != quote) s++;
		if (!*s) {
		    tap_plan("wildmatch");
		    tap_xbail_out("Unmatched quote on line %d of %s:\n# %s",
				  line, *argv, buf);
		}
		end[i] = s;
	    }
	    else {
		if (!*s || *s == '\n') {
		    tap_plan("wildmatch");
		    tap_xbail_out("Not enough strings on line %d of %s:\n# %s",
				  line, *argv, buf);
		}
		string[i] = s;
		while (*++s && *s != ' ' && *s != '\t' && *s != '\n') {}
		end[i] = s;
	    }
	    while (*++s == ' ' || *s == '\t') {}
	}
	*end[0] = *end[1] = '\0';
	run_test(line, flag[0], flag[1], string[0], string[1]);
    }

    if (!wildmatch_errors)
	tap_comment("No wildmatch errors found");
    else {
	tap_comment("%d wildmatch errors found", wildmatch_errors);
	exit_code = EXIT_FAILURE;
    }

#ifdef COMPARE_WITH_FNMATCH
    if (!fnmatch_errors)
	tap_comment("No fnmatch errors found");
    else {
	tap_comment("%d fnmatch errors found");
	exit_code = EXIT_FAILURE;
    }
#endif

    tap_plan("wildmatch");
    return exit_code;
}
