#include "headers.h"

void *thread(void *arg)
{
	usleep(4242);
	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	int i, c, s;
	pid_t p;

	c = atoi(getenv("SPAWN_MAX") ? getenv("SPAWN_MAX") : "16");
	if (c < 0 || c > 4096)
		abort();
	s = atoi(argv[1]);
	p = getpid();

	for (i = 0; i < c; i++) {
		pthread_t t;

		pthread_create(&t, NULL, thread, NULL);
		/* pthread_join(t, NULL); */
	}

	errno = 0;
	kill(p, s);
	return errno;
}
