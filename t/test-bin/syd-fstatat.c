#include "headers.h"

int main(int argc, char *argv[])
{
	int dirfd;
	const char *path;
	struct stat buf;

	if (!strcmp(argv[1], "cwd"))
		dirfd = AT_FDCWD;
	else if (!strcmp(argv[1], "null"))
		dirfd = STDERR_FILENO; /* not a directory */
	else
		dirfd = atoi(argv[1]);
	path = argv[2];

	/* Using fstatat(AT_FDCWD, ...) is not a good idea here as the libc may
	 * actually call the stat() system call instead. */
	errno = 0;
	syscall(SYS_newfstatat, dirfd, path, &buf, 0);
	return errno;
}
