#include "headers.h"

int main(int argc, char *argv[])
{
	int i, c;

	c = atoi(argv[1]);
	if (c < 0 || c > 4096)
		abort();
	for (i = 0; i < c; i++) {
		pid_t pid = fork();
		if (!pid) {
			usleep(4242 + i);
			_exit((i % 254) == 1 ? 7 : (i % 254));
		}
	}

	return 1;
}
