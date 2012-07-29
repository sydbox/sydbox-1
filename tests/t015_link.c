/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc < 3)
		return 125;

	if (link(argv[1], argv[2]) < 0) {
		if (getenv("SYDBOX_TEST_SUCCESS")) {
			perror(__FILE__);
			return 1;
		}
		else if (getenv("SYDBOX_TEST_EPERM") && errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	return getenv("SYDBOX_TEST_SUCCESS") ? 0 : 2;
}
