#include "headers.h"

#define _msg(std, fmt, ...) fprintf(std, "%s:%s():%i: " fmt "\n", __FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define _stderr_msg(fmt, ...) _msg(stderr, fmt, ##__VA_ARGS__)
#define _stderr_pmsg(fmt, ...) _msg(stderr, fmt ": %s", ##__VA_ARGS__, strerror(errno))
#define err(fmt, ...) do { _stderr_msg(fmt, ##__VA_ARGS__); exit(1); } while (0)
#define errp(fmt, ...) do { _stderr_pmsg(fmt, ##__VA_ARGS__); exit(1); } while (0)

typedef struct {
	const char *name;
	int val;
} value_pair;
#define PAIR(x) { #x, x },

int _lookup_val(const value_pair *tbl, const char *name, bool *found)
{
	size_t i;

	*found = true;
	for (i = 0; tbl[i].name; ++i)
		if (!strcmp(name, tbl[i].name))
			return tbl[i].val;

	*found = false;
	return 0;
}
int lookup_val(const value_pair *tbl, const char *name)
{
	bool found;
	int ret = _lookup_val(tbl, name, &found);
	if (!found)
		err("unable to locate '%s'", name);
	return ret;
}

const char *lookup_str(const value_pair *tbl, int val)
{
	size_t i;
	for (i = 0; tbl[i].name; ++i)
		if (tbl[i].val == val)
			return tbl[i].name;
	err("unable to locate '%i'", val);
}

#define make_lookups(section) \
int lookup_##section(const char *str) { return atoi(str) ? (-1) : lookup_val(tbl_##section, str); } \
const char *rev_lookup_##section(int val) { return lookup_str(tbl_##section, val); }

const value_pair tbl_errno[] = {
	{ "Success", 0 },
	PAIR(EACCES)
	PAIR(EAGAIN)
	PAIR(EBADF)
/*	PAIR(EBADFD) POSIX only has EBADF */
	PAIR(EBUSY)
	PAIR(ECANCELED)
	PAIR(ECHILD)
	PAIR(EEXIST)
	PAIR(EFAULT)
	PAIR(EINTR)
	PAIR(EINVAL)
	PAIR(EIO)
	PAIR(EISDIR)
	PAIR(ELOOP)
	PAIR(EMFILE)
	PAIR(EMLINK)
	PAIR(ENAMETOOLONG)
	PAIR(ENOBUFS)
	PAIR(ENODEV)
	PAIR(ENOENT)
	PAIR(ENOEXEC)
	PAIR(ENOMEM)
	PAIR(ENOSPC)
	PAIR(ENOSYS)
	PAIR(ENOTDIR)
	PAIR(ENOTEMPTY)
	PAIR(ENOTSOCK)
	PAIR(ENOTSUP)
	PAIR(ENOTTY)
	PAIR(ENXIO)
	PAIR(EPERM)
	PAIR(ERANGE)
	PAIR(ESPIPE)
	PAIR(ESRCH)
	PAIR(ESTALE)
	PAIR(ETXTBSY)
	{NULL, -1}
};
make_lookups(errno)

const value_pair tbl_signal[] = {
	{ "SIGEXIT", 0 },
	PAIR(SIGABRT)
	PAIR(SIGALRM)
	PAIR(SIGCHLD)
	PAIR(SIGCONT)
	PAIR(SIGHUP)
	PAIR(SIGILL)
	PAIR(SIGINT)
	PAIR(SIGKILL)
	PAIR(SIGPIPE)
	PAIR(SIGQUIT)
	PAIR(SIGSEGV)
	PAIR(SIGSTOP)
	PAIR(SIGTRAP)
	PAIR(SIGTERM)
	PAIR(SIGUSR1)
	PAIR(SIGUSR2)
	{NULL, -1}
};
make_lookups(signal)
