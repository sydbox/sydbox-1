AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .

syddir=$(libexecdir)/$(PACKAGE)/t/valgrind
VALGRIND_SRCS= \
	     analyze.sh \
syd_SCRIPTS= analyze.sh
syd_DATA= default.supp

EXTRA_DIST= $(VALGRIND_SRCS) $(syd_DATA)
