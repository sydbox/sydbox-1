#include "headers.h"

int main(int argc, char *argv[])
{
	if (argc < 2)
		return EINVAL;
	char *pathname = argv[1];
	int flags = O_RDONLY;
	if (argc > 2) {
		for (int i = 2; i < argc; i++) {
			if (!strcmp("async", argv[i]))
				flags |= O_ASYNC;
			else if (!strcmp("direct", argv[i]))
				flags |= O_DIRECT;
			else if (!strcmp("sync", argv[i]))
				flags |= O_SYNC;
			else
				return EINVAL;
		}
	}

	errno = 0;
	int fd = open(pathname, flags);
	if (fd < 0) {
		if (errno == EINVAL)
			return 0;
		return errno;
	}
	return 0;
}
