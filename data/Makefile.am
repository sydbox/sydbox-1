AM_MAKEFLAGS= --no-print-directory
EXTRA_DIST=

sydboxsharedir= $(datadir)/$(PACKAGE)
sydboxshare_DATA= \
		  paludis.syd-1 \
		  sydbox.supp
EXTRA_DIST+= $(sydboxshare_DATA)

dist_doc_DATA= \
	       poems.txt
	       sydbox-logo.svg \
	       sydbox-jade-hexagram.svg

upload: poems.txt
	rsync --progress -ave ssh $< strauss.exherbo.org:public_html/sydbox/
.PHONY: upload
