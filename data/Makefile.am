AM_MAKEFLAGS= --no-print-directory
EXTRA_DIST=

sydboxsharedir= $(datadir)/$(PACKAGE)
sydboxshare_DATA= \
		  default.syd-2 \
		  paludis.syd-2 \
		  firefox.syd-2 \
		  sydbox.bashrc
		  sydbox.supp
EXTRA_DIST+= $(sydboxshare_DATA)

dist_doc_DATA= \
	       poems.txt
	       sydbox-logo.svg \
	       sydbox-jade-hexagram.svg

upload: poems.txt
	rsync --progress -ave ssh $< strauss.exherbo.org:public_html/sydbox/
.PHONY: upload
