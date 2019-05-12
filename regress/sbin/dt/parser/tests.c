/*
 * Regress test for iked payload parser
 *
 * Placed in the public domain
 */

#include "dlang.h"
#include "test_helper.h"

static void parser_tests(void);
static int test_str(const char *);

void
tests(void)
{
	parser_tests();
}

static void parser_tests(void)
{
	TEST_START("Test valid profile probes");
	ASSERT_INT_GE(test_str("profile:s:100"), 1);
	ASSERT_INT_EQ(test_str("profile:s: { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile:s:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile:us:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile:ms:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile:hz:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile:hz:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile::100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("profile:: { test;}"), 0);
	TEST_DONE();

	TEST_START("Test valid interval probes");
	ASSERT_INT_GE(test_str("interval:s:100"), 1);
	ASSERT_INT_EQ(test_str("interval::100 { test; } "), 0);
	ASSERT_INT_EQ(test_str("interval:s:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:us:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:ms:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:hz:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:hz:100 { test;}"), 0);
	TEST_DONE();

	TEST_START("Test valid multiple probes");
	ASSERT_INT_EQ(test_str("interval:us:100 { test;} profile:s:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:us:100 { test;}  profile:s:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:us:100 { test;}\nprofile:s:100 { test;}"), 0);
	ASSERT_INT_EQ(test_str("interval:us:100 { test;}\tprofile:s:100 { test;}"), 0);
	TEST_DONE();

	TEST_START("Test syntax errors");
	ASSERT_INT_GE(test_str("interval:us:100 { test }"), 1);
	ASSERT_INT_GE(test_str("interval:;:100 { test }"), 1);
	ASSERT_INT_GE(test_str("in\nterval:::100 { test }"), 1);
	ASSERT_INT_GE(test_str("interval:us100 { test; }"), 1);
	ASSERT_INT_GE(test_str("interval:us:100  test; }"), 1);
	ASSERT_INT_GE(test_str("interval:us:100 { test; "), 1);
	ASSERT_INT_GE(test_str("interval;us:100 { test; "), 1);
	TEST_DONE();
}

static int test_str(const char *str) {
	return parse_script(str, strlen(str), 1);
}
