#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

int main(void)
{
	kill(getpid(), SIGSTOP);
	return 1;
}
