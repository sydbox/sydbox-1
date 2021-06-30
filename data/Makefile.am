AM_MAKEFLAGS= --no-print-directory
CLEANFILES=
EXTRA_DIST=

EXTRA_DIST+= sydbox.bashrc.in
CLEANFILES+= sydbox.bashrc


sydboxsharedir= $(datadir)/$(PACKAGE)
sydbox.bashrc: sydbox.bashrc.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e 's:@SYDBOX_SHARE_DIR@:$(sydboxsharedir):g' \
		$< > $@
sydboxshare_DATA= \
		  default.syd-2 \
		  paludis.syd-2 \
		  firefox.syd-2 \
		  sydbox.bashrc \
		  sydbox.supp \
		  tao.fortune
sydboxshare_SCRIPTS= tao.pl
EXTRA_DIST+= $(sydboxshare_DATA)

dist_doc_DATA= \
	       poems.txt \
	       sydbox-logo.svg \
	       sydbox-jade-hexagram.svg

upload: poems.txt
	rsync --progress -ave ssh $< strauss.exherbo.org:public_html/sydbox/
.PHONY: upload
