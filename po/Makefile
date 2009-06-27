include Makevars
GETTEXT_PACKAGE=$(DOMAIN)
PO_FILES := $(wildcard *.po)
CONTACT=martin.pitt@ubuntu.com
top_srcdir = ..

all: $(DOMAIN).pot

clean:
	rm -rf mo/
	rm -f $(DOMAIN).pot

# update the pot
$(DOMAIN).pot:
	# we need fake .py files, since current intltool-update
	# currently does not understand a thing like [type: python]
	ln -s apport-gtk $(top_srcdir)/gtk/apport-gtk.py
	ln -s apport-kde $(top_srcdir)/kde/apport-kde.py
	ln -s apport-cli $(top_srcdir)/cli/apport-cli.py
	XGETTEXT_ARGS='--msgid-bugs-address=$(CONTACT)' intltool-update -p --verbose
	rm $(top_srcdir)/gtk/apport-gtk.py $(top_srcdir)/kde/apport-kde.py $(top_srcdir)/cli/apport-cli.py

# merge the new stuff into the po files
merge-po: $(PO_FILES) $(DOMAIN.pot)
	# we need fake .py files, since current intltool-update
	# currently does not understand a thing like [type: python]
	ln -s apport-gtk $(top_srcdir)/gtk/apport-gtk.py
	ln -s apport-kde $(top_srcdir)/kde/apport-kde.py
	ln -s apport-cli $(top_srcdir)/cli/apport-cli.py
	XGETTEXT_ARGS='--msgid-bugs-address=$(CONTACT)' intltool-update -r
	rm $(top_srcdir)/gtk/apport-gtk.py $(top_srcdir)/kde/apport-kde.py $(top_srcdir)/cli/apport-cli.py

# create mo from the pos
%.mo : %.po
	mkdir -p mo/$(subst .po,,$<)/LC_MESSAGES/ 
	msgfmt $< -o mo/$(subst .po,,$<)/LC_MESSAGES/$(DOMAIN).mo 

# generate all *.mo files
build-mo: $(patsubst %.po,%.mo,$(wildcard *.po))
