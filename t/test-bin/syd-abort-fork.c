#include "headers.h"

int main(int argc, char *argv[])
{
	int i, c, s;
	pid_t p;

	c = atoi(argv[1]);
	if (c < 0 || c > 4096)
		abort();
	for (i = 0; i < c; i++) {
		pid_t pid = fork();
		if (!pid) {
			usleep(4242 + i);
			_exit((i % 127) + 1);
		}
	}

	s = atoi(argv[2]);
	p = getpid();
	errno = 0;

	kill(p, s);

	return errno;
}
