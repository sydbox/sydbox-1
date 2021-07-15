H = $(top_builddir)/misc/syd-hilite
AM_MAKEFLAGS= --no-print-directory
AM_YFLAGS= -d
CLEANFILES= \
	    *~ \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.tab.h \
	    *.tab.c

rcmaindir = $(datadir)/$(PACKAGE)/rc
rcmain_HEADERS = rcmain

rcmain: rcmain.syd
	cp -pP $< $@

AM_LDFLAGS=
if SYDBOX_HAVE_READLINE
PROMPT=readline
AM_LDFLAGS+=-lreadline
else
PROMPT=null
endif

AM_CFLAGS=\
	-DPROMPT='"$(PROMPT)"' \
	-DPREFIX='"/usr"' \
	-DDATADIR='"$(rcmaindir)"' \
	-Wall -Wextra -Wno-parentheses \
	-Wno-missing-braces -Wno-missing-field-initializers \
	-Wno-comment -Wno-sign-compare -Wno-unused-parameter \
	-Wno-implicit-fallthrough

RC_SRCS=\
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

lib_LTLIBRARIES = libsyd_rc_@LIBSYD_PC_SLOT@.la
libsyd_rc_@LIBSYD_PC_SLOT@_la_CFLAGS= $(AM_CFLAGS) -DIN_LIBSYD=1 -DMAIN=0
libsyd_rc_@LIBSYD_PC_SLOT@_la_LDFLAGS= $(AM_LDFLAGS)
libsyd_rc_@LIBSYD_PC_SLOT@_la_SOURCES= $(RC_SRCS)

bin_PROGRAMS= syd-rc
syd_rcdir=$(libexecdir)/$(PACKAGE)/bin
syd_rc_PROGRAMS= syd-rc
syd_rc_CFLAGS= $(AM_CFLAGS) -DIN_SYD_RC=1 -DMAIN=1
syd_rc_LDFLAGS= $(AM_LDFLAGS)
syd_rc_SOURCES= $(RC_SRCS)

YFILES=syn.y
y.tab.h y.tab.c: $(YFILES)
	$(YACC) $(AM_YFLAGS) $(YFILES)
x.tab.h: y.tab.h
	cmp -s x.tab.h y.tab.h || cp y.tab.h x.tab.h
BUILT_SOURCES= $(YFILES) x.tab.h
