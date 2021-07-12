H = $(top_builddir)/misc/syd-hilite
AM_MAKEFLAGS= --no-print-directory
AM_YFLAGS= -d
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.tab.h \
	    *.tab.c

#PROMPT=readline
PROMPT=null

lib_LTLIBRARIES = libsyd_rc_@LIBSYD_PC_SLOT@.la
libsyd_rc_@LIBSYD_PC_SLOT@_la_CFLAGS=\
	-DPREFIX='"/usr"' \
	-Wall -Wextra -Wno-parentheses \
	-Wno-missing-braces -Wno-missing-field-initializers \
	-Wno-comment -Wno-sign-compare -Wno-unused-parameter \
	-Wno-implicit-fallthrough
libsyd_rc_@LIBSYD_PC_SLOT@_la_SOURCES=\
		exec.h\
		fns.h\
		getflags.h\
		io.h\
		rc.h\
		unix.h\
		code.c\
		exec.c\
		getflags.c\
		glob.c\
		here.c\
		io.c\
		lex.c\
		pcmd.c\
		pfnc.c\
		simple.c\
		subr.c\
		trap.c\
		tree.c\
		var.c\
		unix.c\
		havefork.c\
		prompt-$(PROMPT).c\
		y.tab.c \
		y.tab.h \
		x.tab.h

YFILES=syn.y
y.tab.h y.tab.c: $(YFILES)
	$(YACC) $(AM_YFLAGS) $(YFILES)
x.tab.h: y.tab.h
	cmp -s x.tab.h y.tab.h || cp y.tab.h x.tab.h
BUILT_SOURCES= $(YFILES) x.tab.h
