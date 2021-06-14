AM_MAKEFLAGS= --no-print-directory
ACLOCAL_AMFLAGS= -I m4 ${ACLOCAL_FLAGS}
AUTOMAKE_OPTIONS= dist-bzip2 no-dist-gzip std-options subdir-objects foreign

CLEANFILES= *~
MAINTAINERCLEANFILES= \
		      Makefile.in \
		      configure \
		      aclocal.m4 \
		      config.h \
		      config.h.in \
		      INSTALL

EXTRA_DIST= \
	    autogen.sh \
	    tao/make.txt \
	    tao/art/art-pink-floyd.txt \
	    tao/art/art-piper.txt \
	    tao/art/art-see-emily-play.txt

PANDORA_EXTRA_DIST=\
		   build.rs \
		   Cargo.toml \
		   Cargo.lock \
		   src/pandora.rs
EXTRA_DIST+= $(PANDORA_EXTRA_DIST)

dist_doc_DATA= \
	       BUGS \
	       COPYING \
	       LICENSE \
	       README \
	       KERNEL.md \
	       man/ptrace-ntpl.txt

DISTCHECK_CONFIGURE_FLAGS= \
			   --enable-seccomp \
			   --enable-debug

BUILT_SOURCES = .version
EXTRA_DIST+= \
	     .version \
	     ChangeLog \
	     CREDITS.in \
	     maint/gitlog-to-changelog
$(srcdir)/.version:
	$(AM_V_GEN)echo $(VERSION) > $@-t && mv $@-t $@

if MAINTAINER_MODE

# For v1.0.0, do:
# gen_changelog_start_date = 2015-01-12 12:00
# This includes all and we're fine with it.
gen_changelog_start_date = 1999-08-17 03:02
$(srcdir)/ChangeLog: $(srcdir)/maint/gitlog-to-changelog $(srcdir)/Makefile.in \
		     $(srcdir)/.version
	@rm -f $@.new
	(cd $(srcdir); \
	 ./maint/gitlog-to-changelog --append-dot \
	   --since='$(gen_changelog_start_date)'; \
	 echo; echo; echo '' \
	) > $@.new
	chmod 444 $@.new
	mv -f $@.new $@

$(srcdir)/CREDITS: $(srcdir)/CREDITS.in $(srcdir)/.mailmap \
		   $(srcdir)/Makefile.in $(srcdir)/.version
	$(AM_V_GEN)							\
	(								\
	  D="$(D)";							\
	  export D;							\
	  cd $(srcdir);							\
	  sed '/^##/,$$d' CREDITS.in;					\
	  sed -n '1,/^##>/d; s/   */\t/; s/^./&/p' CREDITS.in		\
	    | maint/gen-contributors-list.sh - -e HEAD --initial	\
	    | sed 's/\t/ /g; s/^/\t/'					\
	) > $@-t && mv $@-t $@

export TAR_OPTIONS = --owner=0 --group=0 --numeric-owner --mode=go-w,go+rX

endif

TAR_FILE= $(PACKAGE)-$(VERSION).tar.bz2
SHA1_FILE= $(TAR_FILE).sha1sum
GPG_FILE= $(SHA1_FILE).asc

.PHONY: doxygen
doxygen: all
	$(MAKE) -C doc $@

$(SHA1_FILE): dist
	@echo "SHA1 $(TAR_FILE)"
	sha1sum $(TAR_FILE) > $(SHA1_FILE)

$(GPG_FILE): $(SHA1_FILE)
	@echo "SIGN $(SHA1_FILE)"
	gpg --detach-sign --armor $(SHA1_FILE)

.PHONY: upload
upload:
	$(MAKE) -C data upload
	$(MAKE) -C man upload

.PHONY: upload-release
upload-release: upload $(SHA1_FILE) $(GPG_FILE)
	rsync --partial --progress -ave ssh $(TAR_FILE) $(SHA1_FILE) $(GPG_FILE) strauss.exherbo.org:public_html/sydbox/
	rsync --partial --progress -ave ssh $(TAR_FILE) $(SHA1_FILE) $(GPG_FILE) strauss.exherbo.org:/srv/www/dev.exherbo.org/distfiles/sydbox

.PHONY: jenkins
jenkins:
	maint/jenkins-build.sh

coverity-build: clean
	cov-build --dir cov-int ${MAKE} ${AM_MAKEFLAGS} check-build

coverity-tarball: coverity-build
	@if git rev-parse HEAD &> /dev/null; then \
		rev_full=$$(git rev-parse HEAD); \
		rev=$$(echo $$rev_full | cut -c1-8); \
	else \
		rev_full=$$(date --iso-8601=date); \
		rev=$$rev_full; \
	fi; \
	tar czf sydbox-coverity_$$rev.tar.gz cov-int; \
	echo " HEAD revision: $$rev_full"; \
	ls -l sydbox-coverity_$$rev.tar.gz

.PHONY: coveralls
coveralls:
	coveralls \
		--exclude t \
		--exclude tests \
		--exclude target \
		--gcov-options '\-lp'

check-build: all
	${MAKE} ${AM_MAKEFLAGS} -C syd check-build
	${MAKE} ${AM_MAKEFLAGS} -C t check-build

check-code-coverage: check-build
	${MAKE} ${AM_MAKEFLAGS} -C t check-code-coverage

.PHONY: coveralls
coveralls:
	coveralls \
		--exclude t \
		--exclude tests \
		--exclude target \
		--gcov-options '\-lp'

check-build: all
	${MAKE} ${AM_MAKEFLAGS} -C syd check-build
	${MAKE} ${AM_MAKEFLAGS} -C t check-build

check-code-coverage: check-build
	${MAKE} ${AM_MAKEFLAGS} -C t check-code-coverage

SUBDIRS= syd src data man t .
