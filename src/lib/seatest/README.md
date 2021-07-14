# Seatest

A simple unit testing framework for C based on the xUnit style of unit testing. Ideal for Test Driven Development (TDD). Designed to be portable.

If you are new to TDD / Unit Testing, you may wish to jump straight to Getting Started.

If you have experience with other xUnit type frameworks, you may wish to read through the general technical overview of SeaTest.

<!-- markdownlint-disable MD033 MD004 -->
<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
<!-- TOC depthFrom:2 updateOnSave:true -->

- [Features](#features)
- [Asserts](#asserts)
- [Seatest Hello World](#seatest-hello-world)
- [Fixtures](#fixtures)
- [Getting Started](#getting-started)
- [Abort tests on failures](#abort-tests-on-failures)
- [Meta](#meta)
	- [Release Notes](#release-notes)

<!-- /TOC -->
<!-- markdownlint-restore -->
<!-- Due to a bug in Markdown TOC, the table is formatted incorrectly if tab indentation is set other than 4. Due to another bug, this comment must be *after* the TOC entry. -->

## Features

- xUnit style asserts
- Fixtures
- Setup / Teardown
- Global Setup / Teardown
- Ability to selectively run Tests / Fixtures
- Testing framework contained in one .h and one .c
- Easily extensible for custom asserts
- No memory allocation used!
- Simple Syntax with no CRUFT
- Cross platform

## Asserts

- assert_true
- assert_false
- assert_int_equal
- assert_ulong_equal
- assert_size_t_equal
- assert_string_equal
- assert_n_array_equal
- assert_bit_set
- assert_bit_not_set
- assert_bit_mask_matches
- assert_fail
- assert_float_equal
- assert_double_equal
- assert_string_contains
- assert_string_doesnt_contain
- assert_string_starts_with
- assert_string_ends_with

## Seatest Hello World

```c
#include "seatest.h"
//
// create a test...
//
void test_hello_world()
{
        char *s = "hello world!";
        assert_string_equal("hello world!", s);
        assert_string_contains("hello", s);
        assert_string_doesnt_contain("goodbye", s);
        assert_string_ends_with("!", s);
        assert_string_starts_with("hell", s);
}

//
// put the test into a fixture...
//
void test_fixture_hello( void )
{
        test_fixture_start();
        run_test(test_hello_world);
        test_fixture_end();
}

//
// put the fixture into a suite...
//
void all_tests( void )
{
        test_fixture_hello();
}

//
// run the suite!
//
int main( int argc, char** argv )
{
        return run_tests(all_tests);
}
```

## Fixtures

In many xUnit style testing frameworks, tests and testfixtures are automatically discovered. So all you do is write your test, or fixture, and they are automatically run. Which is great! You never forget to include a test. However in C, there is no language mechanism to do this. (Some of the C unit testing frameworks make use of something like python to find the tests automatically.)

So Seatest requires you to explicitly register all your tests and fixtures. If you are in the habit of "red green refactor", this limitation shouldn't be too much of a problem. The main reason for this is that the framework needs to be easily used in embedded environments / compilers / IDEs. The current prime target being PICs and the MPLAB IDE. So things are kept to pretty vanilla C code.

Seatest was built to support embedded development using a dual compiler approach. This approach involves developing the bulk of the code / tests in a rich C development environment, like Visual Studio, and then cross compiling with the more limited embedded C compiler to check the unit tests also run on the target device.

One of the big factors was to make sure Seatest didn't use any dynamic memory allocation (like malloc, etc). Or store a big list of tests in some structure. All the test fixtures and tests are created through the structure of the code itself. Making it simple, quick, and very straightforward.

The general approach to fixtures generally looks like the following:

```c
void my_test_fixture()
{
        test_fixture_start();
        fixture_setup(my_test_setup);
        fixture_teardown(my_test_teardown);

        run_test(test_one);
        run_test(test_two);

        test_fixture_end();
}
```

## Getting Started

Note, this section is currently getting built up and might seem a bit incomplete at times. It needs building into a full tutorial and a description on how to do embedded C unit testing.

1. Download the source code

2. include "seatest.c" and "seatest.h" in your project, make sure the .h is in a directory your compiler will find when including headers.

3. create a function called something like "alltests" which will combine all your test suites together

4. In your main create the test runner

5. Create a test suite

6. Create tests

7. Run

## Abort tests on failures

Normally Seatest will run all asserts in a test no matter whether they pass or fail.

You can fine tune the behavior of Seatest using two APIs.

```c
void seatest_global_set_test_fixture_failed_limit_default(int limit);
```

This function updates the default limit for failed assertions in every test fixture run after this API is called. If `limit` is `-1`, no limit is applied.

```c
void seatest_test_fixture_set_failed_limit(int limit);
```

This function sets the limit for failed assertions in the *current* test fixture. It only affects assertions that fail after this API is called, so if 5 errors have occurred already in the current fixture, and you call `seatest_test_fixture_set_failed_limit(0)`, the fixture still proceeds until the next assertion fails.

```c
void seatest_global_set_failed_limit(int limit);
```

This function sets the limit for failed assertions in the entire test run. It only affects assertions that fail after this API is called, so if 5 errors have occurred already in the current fixture, and you call `seatest_global_set_failed_limit(0)`, the fixture still proceeds until the next assertion fails.

## Meta

### Release Notes

- `v2.0.0-alpha2`: add `seatest_global_set_failed_limit()` API.

- `v2.0.0-alpha1`: add `seatest_global_set_test_fixture_failed_limit_default()` and `seatest_test_fixture_set_failed_limit()` APIs.

- `v1.1.0`: first MCCI version
