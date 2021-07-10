static char *ret_str;
#define FUNC realpath_mode
#define SFUNC "realpath_mode"
#define FUNC_STR "\"%s\", %d, %p"
#define FUNC_IMP file, mode, ((void *)&ret_str)
#define ARG_CNT 3
#define ARG_USE "<file> <realpath_mode> <NULL | realpath>"
#define RET_STR ret_str
#define EXP_STR exp_str

#define process_args() \
	s = argv[i++]; \
	const char *file = f_get_file(s); \
	\
	s = argv[i++]; \
	int mode = get_realpath_mode(s); \
	\
	s = argv[i++]; \
	const char *exp_str = f_get_file(s);

#include "syd-conf.h"
#include "bsd-compat.h"
#include "file.h"
#include "test-skel-1.c"
