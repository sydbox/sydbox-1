#include "seatest.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#ifdef WIN32
#include "windows.h"
int seatest_is_string_equal_i(const char* s1, const char* s2)
{
	#pragma warning(disable: 4996)
	return _stricmp(s1, s2) == 0;
}

#else
#include <strings.h>
unsigned int GetTickCount() { return 0;}
void _getch( void ) { }
int seatest_is_string_equal_i(const char* s1, const char* s2)
{
	return strcasecmp(s1, s2) == 0;
}
#endif

// seatest_snprintf()
#ifndef WIN32
# include <limits.h>
# include <stdarg.h>
#endif // !WIN32

size_t seatest_snprintf(char *pOutbuf, size_t nOutbuf, const char *pFmt, ...)
{
	va_list ap;
	int iResult;
	size_t nResult;

	if (pOutbuf == NULL)
		return 0;
	if (nOutbuf == 0 || nOutbuf > INT_MAX)
		return 0;

	va_start(ap, pFmt);

#ifdef WIN32
# pragma warning(push)
# pragma warning(disable:4996)
#endif // WIN32
	iResult = vsnprintf(pOutbuf, nOutbuf - 1, pFmt, ap);
#ifdef WIN32
# pragma warning(pop)
#endif // WIN32

	va_end(ap);

	if (iResult < 0)
	{
		iResult = 0;
	}
	nResult = iResult;

	if (nResult > nOutbuf - 1)
	{
		nResult = nOutbuf - 1;
	}

	pOutbuf[nResult] = 0; 
	return nResult;
}

#ifdef SEATEST_INTERNAL_TESTS
static int sea_test_last_passed = 0;
#endif

#define SEATEST_RET_ERROR								(-1)
#define SEATEST_RET_OK									0
#define SEATEST_RET_FAILED_COUNT(tests_failed_count)	(tests_failed_count)

typedef enum
{
	SEATEST_DISPLAY_TESTS,
	SEATEST_RUN_TESTS,
	SEATEST_DO_NOTHING,
	SEATEST_DO_ABORT
} seatest_action_t;

typedef struct
{
	int argc;
	char** argv;
	seatest_action_t action;
} seatest_testrunner_t;
static int seatest_screen_width = 70;
static int sea_tests_run = 0;
static int sea_tests_passed = 0;
static int sea_tests_failed = 0;
static int sea_test_functions_failed = 0;
static int seatest_display_only = 0;
static int seatest_verbose = 0;
static int vs_mode = 0;
static int seatest_machine_readable = 0;
static const char* seatest_current_fixture;
static const char* seatest_current_fixture_path;
static char seatest_magic_marker[20] = "";

static seatest_void_void seatest_suite_setup_func = 0;
static seatest_void_void seatest_suite_teardown_func = 0;
static seatest_void_void seatest_fixture_setup = 0;
static seatest_void_void seatest_fixture_teardown = 0;

/* for aborting tests */
jmp_buf seatest_test_abort_env;

seatest_simple_test_result_fn_t *seatest_simple_test_result = seatest_simple_test_result_log;

void suite_setup(seatest_void_void setup)
{
	seatest_suite_setup_func = setup;
}
void suite_teardown(seatest_void_void teardown)
{
	seatest_suite_teardown_func = teardown;
}

int seatest_is_display_only()
{
	return seatest_display_only;
}

void seatest_suite_setup( void )
{
	if(seatest_suite_setup_func != 0) seatest_suite_setup_func();
}

void seatest_suite_teardown( void )
{
	if(seatest_suite_teardown_func != 0) seatest_suite_teardown_func();
}

void fixture_setup(void (*setup)( void ))
{
	seatest_fixture_setup = setup;
}
void fixture_teardown(void (*teardown)( void ))
{
	seatest_fixture_teardown = teardown;
}

void seatest_setup( void )
{
	if(seatest_fixture_setup != 0) seatest_fixture_setup();
}

void seatest_teardown( void )
{
	if(seatest_fixture_teardown != 0) seatest_fixture_teardown();
}

const char* test_file_name(const char* path)
{
	const char* file = path + strlen(path);
	while(file != path && *file != '\\' && *file != '/') file--;
	if(*file == '\\' || *file == '/') file++;
	return file;
}

static int seatest_fixture_tests_run;
static int seatest_fixture_test_functions_failed;
static int seatest_fixture_tests_failed;
static int seatest_fixture_tests_failed_limit;
static int seatest_fixture_tests_failed_limit_default = -1;

static int check_reached_test_limit(int my_sea_tests_failed)
{
	if (seatest_fixture_tests_failed_limit < 0)
		return 0;

	int const fixture_tests_failed = my_sea_tests_failed - seatest_fixture_tests_failed;
	if (fixture_tests_failed > seatest_fixture_tests_failed_limit)
		return 1;
	else
		return 0;
}

void seatest_simple_test_result_log(int passed, const char* reason, const char* function, unsigned int line)
{
	if (!passed)
	{

		if(seatest_machine_readable)
		{
			if (vs_mode)
			{
				printf("%s (%u)		%s,%s" SEATEST_NL, seatest_current_fixture_path, line, function, reason );
			}
			else
			{
				printf("%s%s,%s,%u,%s" SEATEST_NL, seatest_magic_marker, seatest_current_fixture_path, function, line, reason );
			}

		}
		else
		{
			if ( vs_mode )
			{
				printf("%s (%u)		%s,%s" SEATEST_NL, seatest_current_fixture_path, line, function, reason );
			}
			else
			{
				printf("%-30s Line %-5d %s" SEATEST_NL, function, line, reason );
			}
		}
		sea_tests_failed++;

		if (check_reached_test_limit(sea_tests_failed))
		{
			printf("Failure limit(%d) exceeded; test has been finished with failure." SEATEST_NL, seatest_fixture_tests_failed_limit);
			longjmp(seatest_test_abort_env, 1);
		}
		#ifdef ABORT_TEST_IF_ASSERT_FAIL
		printf("Test has been finished with failure." SEATEST_NL);
		longjmp(seatest_test_abort_env,1);
		#endif
	}
	else
	{
		if(seatest_verbose)
		{
			if(seatest_machine_readable)
			{
				printf("%s%s,%s,%u,Passed" SEATEST_NL, seatest_magic_marker, seatest_current_fixture_path, function, line );
			}
			else
			{
				printf("%-30s Line %-5d Passed" SEATEST_NL, function, line);
			}
		}
		sea_tests_passed++;
	}
}

void seatest_assert_true(int test, const char* function, unsigned int line)
{
	seatest_simple_test_result(test, "Should have been true", function, line);

}

void seatest_assert_false(int test, const char* function, unsigned int line)
{
	seatest_simple_test_result(!test, "Should have been false", function, line);
}


void seatest_assert_int_equal(int expected, int actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected %d but was %d", expected, actual);
	seatest_simple_test_result(expected==actual, s, function, line);
}

void seatest_assert_ulong_equal(unsigned long expected, unsigned long actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected %lu but was %lu", expected, actual);
	seatest_simple_test_result(expected==actual, s, function, line);
}

void seatest_assert_size_t_equal(size_t expected, size_t actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected %" PRIuMAX " but was %" PRIuMAX, (uintmax_t) expected, (uintmax_t) actual);
	seatest_simple_test_result(expected==actual, s, function, line);
}

void seatest_assert_float_equal( float expected, float actual, float delta, const char* function, unsigned int line )
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	float result = expected-actual;
	seatest_snprintf(s, sizeof(s), "Expected %f but was %f", expected, actual);
	if(result < 0.0) result = 0.0f - result;
	seatest_simple_test_result( result <= delta, s, function, line);
}

void seatest_assert_double_equal( double expected, double actual, double delta, const char* function, unsigned int line )
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	double result = expected-actual;
	seatest_snprintf(s, sizeof(s), "Expected %f but was %f", expected, actual);
	if(result < 0.0) result = 0.0 - result;
	seatest_simple_test_result( result <= delta, s, function, line);
}

void seatest_assert_string_equal(const char* expected, const char* actual, const char* function, unsigned int line)
{
        int comparison;
	char s[SEATEST_PRINT_BUFFER_SIZE];

	if ((expected == (char *)0) && (actual == (char *)0))
	{
          seatest_snprintf(s, sizeof(s), "Expected <NULL> but was <NULL>");
	  comparison = 1;
	}
        else if (expected == (char *)0)
	{
	  seatest_snprintf(s, sizeof(s), "Expected <NULL> but was \"%s\"", actual);
	  comparison = 0;
	}
        else if (actual == (char *)0)
	{
	  seatest_snprintf(s, sizeof(s), "Expected \"%s\" but was <NULL>", expected);
	  comparison = 0;
	}
	else
	{
	  comparison = strcmp(expected, actual) == 0;
	  seatest_snprintf(s, sizeof(s), "Expected \"%s\" but was \"%s\"", expected, actual);
	}

	seatest_simple_test_result(comparison, s, function, line);
}

void seatest_assert_string_ends_with(const char* expected, const char* actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected \"%s\" to end with \"%s\"", actual, expected);
	seatest_simple_test_result(strcmp(expected, actual+(strlen(actual)-strlen(expected)))==0, s, function, line);
}

void seatest_assert_string_starts_with(const char* expected, const char* actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected \"%s\" to start with \"%s\"", actual, expected);
	seatest_simple_test_result(strncmp(expected, actual, strlen(expected))==0, s, function, line);
}

void seatest_assert_string_contains(const char* expected, const char* actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected \"%s\" to be in \"%s\"", expected, actual);
	seatest_simple_test_result(strstr(actual, expected)!=0, s, function, line);
}

void seatest_assert_string_doesnt_contain(const char* expected, const char* actual, const char* function, unsigned int line)
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "Expected \"%s\" not to have \"%s\" in it", actual, expected);
	seatest_simple_test_result(strstr(actual, expected)==0, s, function, line);
}

#ifdef WIN32
# pragma warning(disable : 4100)
#endif
void seatest_run_test(const char* fixture, const char* test)
{
	sea_tests_run++;
}

void seatest_header_printer(const char* s, int length, char f)
{
	int l = (int) strlen(s);
	int d = (length- (l + 2)) / 2;
	int i;
	if(seatest_is_display_only() || seatest_machine_readable) return;
	for(i = 0; i<d; i++) printf("%c",f);
	if(l==0) printf("%c%c", f, f);
	else printf(" %s ", s);
	for(i = (d+l+2); i<length; i++) printf("%c",f);
	printf(SEATEST_NL);
}


void seatest_test_fixture_start(const char* filepath)
{
	seatest_current_fixture_path = filepath;
	seatest_current_fixture = test_file_name(filepath);
	seatest_header_printer(seatest_current_fixture, seatest_screen_width, '-');
	seatest_fixture_tests_failed = sea_tests_failed;
	seatest_fixture_tests_run = sea_tests_run;
	seatest_fixture_test_functions_failed = sea_test_functions_failed;
	seatest_fixture_teardown = 0;
	seatest_fixture_setup = 0;
	seatest_fixture_tests_failed_limit = seatest_fixture_tests_failed_limit_default;
}

void seatest_test_fixture_set_failed_limit(int limit)
{
	seatest_fixture_tests_failed_limit = limit;
}

void seatest_global_set_test_fixture_failed_limit_default(int limit)
{
	seatest_fixture_tests_failed_limit_default = limit;
}

void seatest_test_fixture_end()
{
	char s[SEATEST_PRINT_BUFFER_SIZE];
	seatest_snprintf(s, sizeof(s), "%d run  %d failed  %d asserts failed",
		sea_tests_run-seatest_fixture_tests_run,
		sea_test_functions_failed-seatest_fixture_test_functions_failed,
		sea_tests_failed-seatest_fixture_tests_failed
		);
	seatest_header_printer(s, seatest_screen_width, ' ');
	if(seatest_is_display_only() || seatest_machine_readable) return;
	printf(SEATEST_NL);
}

static const char* seatest_fixture_filter = 0;
static const char* seatest_test_filter = 0;

/* TODO(tmm@mcci.com): rename to seatest_set_fixture_filter */
void fixture_filter(const char* filter)
{
	seatest_fixture_filter = filter;
}

/* TODO(tmm@mcci.com): rename to setteast_set_test_filter() */
void test_filter(const char* filter)
{
	seatest_test_filter = filter;
}

static void set_magic_marker(const char* marker)
{
	if(marker == NULL) return;
	strcpy(seatest_magic_marker, marker);
}

void seatest_display_test(const char* fixture_name, const char* test_name)
{
	if(test_name == NULL) return;
	printf("%s,%s" SEATEST_NL, fixture_name, test_name);
}

int seatest_should_run(const char* fixture, const char* test)
{
	int run = 1;

	if(seatest_fixture_filter)
	{
		const char * const sFixture = test_file_name(fixture);
		if(strncmp(seatest_fixture_filter, sFixture, strlen(seatest_fixture_filter)) != 0) run = 0;
	}
	if(seatest_test_filter && test != NULL)
	{
		if(strncmp(seatest_test_filter, test, strlen(seatest_test_filter)) != 0) run = 0;
	}

	if(run && seatest_display_only)
	{
		seatest_display_test(fixture, test);
		run = 0;
	}
	return run;
}

void seatest_test(const char* fixture, const char* test, void (*test_function)(void))
{
	const int save_sea_tests_failed = sea_tests_failed;

	seatest_suite_setup();
	seatest_setup();

	if (! setjmp(seatest_test_abort_env))
	{
		test_function();
	}

	seatest_teardown();
	seatest_suite_teardown();

	if (sea_tests_failed != save_sea_tests_failed)
		++sea_test_functions_failed;

	seatest_run_test(fixture, test);
}

static int seatest_finish(unsigned long timediff)
{
	char version[40];
	char s[80];
	if(seatest_is_display_only() || seatest_machine_readable) return SEATEST_RET_OK;
	seatest_snprintf(version, sizeof(version), "SEATEST v%s", SEATEST_VERSION);
	printf(SEATEST_NL SEATEST_NL);
	seatest_header_printer(version, seatest_screen_width, '=');
	printf(SEATEST_NL);
	if (sea_tests_failed > 0) {
		seatest_header_printer("Failed", seatest_screen_width, ' ');
		seatest_snprintf(s, sizeof(s), "%d tests run  %d tests failed  %d assertions failed",
			sea_tests_run, sea_test_functions_failed, sea_tests_failed
			);
	}
	else {
		seatest_header_printer("ALL TESTS PASSED", seatest_screen_width, ' ');
		seatest_snprintf(s, sizeof(s), "%d tests run", sea_tests_run);
	}
	seatest_header_printer(s, seatest_screen_width, ' ');
	seatest_snprintf(s, sizeof(s), "in %lu ms", timediff);
	seatest_header_printer(s, seatest_screen_width, ' ');
	printf(SEATEST_NL);
	seatest_header_printer("", seatest_screen_width, '=');

	return SEATEST_RET_FAILED_COUNT(sea_tests_failed);
}

int run_tests(seatest_void_void tests)
{
	unsigned long end;
	unsigned long start = GetTickCount();
	tests();
	end = GetTickCount();

	return seatest_finish(end - start);
}

void seatest_show_usage( void )
{
	printf("Usage: [-t <testname>] [-f <fixturename>] [-d] [help] [-v] [-m] [-k <marker>]" SEATEST_NL);
}
void seatest_show_help( void )
{
	seatest_show_usage();
	printf("Flags:" SEATEST_NL);
	printf("\thelp:\twill display this help" SEATEST_NL);
	printf("\t-t:\twill only run tests that match <testname>" SEATEST_NL);
	printf("\t-f:\twill only run fixtures that match <fixturename>" SEATEST_NL);
	printf("\t-d:\twill just display test names and fixtures without" SEATEST_NL);
	printf("\t   \trunning the test" SEATEST_NL);
	printf("\t-v:\twill print a more verbose version of the test run" SEATEST_NL);
	printf("\t-m:\twill print a machine readable format of the test run, i.e.:" SEATEST_NL);
	printf("\t   \t<textfixture>,<testname>,<linenumber>,<testresult><EOL>" SEATEST_NL);
	printf("\t-vs:\tcauses messages to be adapted to match Visual Studio" SEATEST_NL);
	printf("\t   \tcode browsing" SEATEST_NL);
	printf("\t-k:\twill prepend <marker> before machine readable output;" SEATEST_NL);
	printf("\t   \t<marker> cannot start with a '-'" SEATEST_NL);
}


int seatest_commandline_has_value_after(seatest_testrunner_t* runner, int arg)
{
	if(!((arg+1) < runner->argc)) return 0;
	if(runner->argv[arg+1][0]=='-') return 0;
	return 1;
}

int seatest_parse_commandline_option_with_value(seatest_testrunner_t* runner, int arg, char* option, seatest_void_string setter)
{
	if(seatest_is_string_equal_i(runner->argv[arg], option))
	{
		if(!seatest_commandline_has_value_after(runner, arg))
		{
			printf("Error: The %s option expects to be followed by a value" SEATEST_NL, option);
			runner->action = SEATEST_DO_ABORT;
			return 0;
		}
		setter(runner->argv[arg+1]);
		return 1;
	}
	return 0;
}

void seatest_interpret_commandline(seatest_testrunner_t* runner)
{
	int arg;
	for(arg=1; (arg < runner->argc) && (runner->action != SEATEST_DO_ABORT); arg++)
	{
		if(seatest_is_string_equal_i(runner->argv[arg], "help") ||
		   seatest_is_string_equal_i(runner->argv[arg], "--help"))
		{
			seatest_show_help();
			runner->action = SEATEST_DO_NOTHING;
			return;
		}
		else if(seatest_is_string_equal_i(runner->argv[arg], "-d")) runner->action = SEATEST_DISPLAY_TESTS;
		else if(seatest_is_string_equal_i(runner->argv[arg], "-v")) seatest_verbose = 1;
		else if(seatest_is_string_equal_i(runner->argv[arg], "-vs")) vs_mode = 1;
		else if(seatest_is_string_equal_i(runner->argv[arg], "-m")) seatest_machine_readable = 1;
		else if(seatest_parse_commandline_option_with_value(runner,arg,"-t", test_filter)) arg++;
		else if(seatest_parse_commandline_option_with_value(runner,arg,"-f", fixture_filter)) arg++;
		else if(seatest_parse_commandline_option_with_value(runner,arg,"-k", set_magic_marker)) arg++;
		else
		{
			printf("unknown option: %s" SEATEST_NL, runner->argv[arg]);
			seatest_show_usage();
			runner->action = SEATEST_DO_ABORT;
		}
	}
}

void seatest_testrunner_create(seatest_testrunner_t* runner, int argc, char** argv )
{
	runner->action = SEATEST_RUN_TESTS;
	runner->argc = argc;
	runner->argv = argv;
	seatest_interpret_commandline(runner);
}

int seatest_testrunner(int argc, char** argv, seatest_void_void tests, seatest_void_void setup, seatest_void_void teardown)
{
	seatest_testrunner_t runner;
	seatest_testrunner_create(&runner, argc, argv);
	switch(runner.action)
	{
	case SEATEST_DISPLAY_TESTS:
		{
			seatest_display_only = 1;
			run_tests(tests);
			return SEATEST_RET_OK;
		}
	case SEATEST_RUN_TESTS:
		{
			seatest_display_only = 0;
			suite_setup(setup);
			suite_teardown(teardown);
			return run_tests(tests);
		}
	case SEATEST_DO_NOTHING:
		{
			return SEATEST_RET_OK;
		}
	case SEATEST_DO_ABORT:
	default:
		{
			/* there was an error which should of been already printed out. */
			return SEATEST_RET_ERROR;
		}
	}
}

#ifdef SEATEST_INTERNAL_TESTS
void seatest_simple_test_result_nolog(int passed, const char* reason, const char* function, unsigned int line)
{
  sea_test_last_passed = passed;
}

void seatest_assert_last_passed()
{
  assert_int_equal(1, sea_test_last_passed);
}

void seatest_assert_last_failed()
{
  assert_int_equal(0, sea_test_last_passed);
}

void seatest_disable_logging()
{
  seatest_simple_test_result = seatest_simple_test_result_nolog;
}

void seatest_enable_logging()
{
  seatest_simple_test_result = seatest_simple_test_result_log;
}
#endif
