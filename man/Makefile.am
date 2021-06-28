AM_MAKEFLAGS= --no-print-directory
CLEANFILES= \
	    syd.1 \
	    syd-format.1 \
	    syd.html \
	    syd-format.html \
	    syd.ent
EXTRA_DIST= \
	    syd.xml \
	    syd-format.xml \
	    syd.ent.in

if HAVE_XSLTPROC
XSLTPROC_FLAGS= \
		--encoding "'UTF-8'" \
		--nonet \
		--param funcsynopsis.style "'ansi'" \
		--path "$(top_builddir)/man"

BUILT_SOURCES= syd.ent
%.ent: %.ent.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s|:SYDBOX_API_VERSION:|$(SYDBOX_API_VERSION)|" \
		-e "s|:SYDBOX_FNAME_EXT:|$(SYDBOX_FNAME_EXT)|" \
		-e "s|:VERSION:|$(VERSION)|" \
		-e "s|:GITHEAD:|$(GITHEAD)|" \
		$< > $@

%.1: %.xml syd.ent
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

%.html: %.xml syd.ent
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

dist_man_MANS= \
	       syd.1 \
	       syd-format.1
dist_html_DATA= \
		syd.html \
		syd-format.html

upload: syd.html syd-format.html
	rsync --progress -ave ssh syd.html dev.exherbo.org:public_html/sydbox/sydbox.html
	rsync --progress -ave ssh syd.html dev.exherbo.org:www/sydbox.html
	rsync --progress -ave ssh syd-format.html dev.exherbo.org:public_html/sydbox/
.PHONY: upload
else
syd.1:
	@echo "You don't have xsltproc installed!"
	exit 1
syd.html:
	@echo "You don't have xsltproc installed!"
	exit 1
upload-html:
	@echo "Not uploading HTML documentation"
	exit 0
endif # HAVE_XSLTPROC
