AM_MAKEFLAGS= --no-print-directory
CLEANFILES= \
	    sydbox.1 \
	    sydfmt.1 \
	    sydbox.html \
	    sydfmt.html \
	    sydbox.ent
EXTRA_DIST= \
	    sydbox.xml \
	    sydfmt.xml \
	    sydbox.ent.in

if HAVE_XSLTPROC
XSLTPROC_FLAGS= \
		--encoding "'UTF-8'" \
		--nonet \
		--param funcsynopsis.style "'ansi'" \
		--path "$(top_builddir)/man"

BUILT_SOURCES= sydbox.ent
%.ent: %.ent.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s|:SYDBOX_API_VERSION:|$(SYDBOX_API_VERSION)|" \
		-e "s|:SYDBOX_FNAME_EXT:|$(SYDBOX_FNAME_EXT)|" \
		-e "s|:VERSION:|$(VERSION)|" \
		-e "s|:GITHEAD:|$(GITHEAD)|" \
		$< > $@

%.1: %.xml sydbox.ent
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

%.html: %.xml sydbox.ent
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

dist_man_MANS= \
	       sydbox.1 \
	       sydfmt.1
dist_html_DATA= \
		sydbox.html \
		sydfmt.html

upload: sydbox.html sydfmt.html
	rsync --progress -ave ssh sydbox.html strauss.exherbo.org:public_html/sydbox/
	rsync --progress -ave ssh sydfmt.html strauss.exherbo.org:public_html/sydbox/
.PHONY: upload
else
sydbox.1:
	@echo "You don't have xsltproc installed!"
	exit 1
sydbox.html:
	@echo "You don't have xsltproc installed!"
	exit 1
upload-html:
	@echo "Not uploading HTML documentation"
	exit 0
endif # HAVE_XSLTPROC
