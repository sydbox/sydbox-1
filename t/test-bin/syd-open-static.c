#include "headers.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
		return EINVAL;
	char *pathname = argv[1];

	errno = 0;
	int fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return errno;
	return 0;
}
