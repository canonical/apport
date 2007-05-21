GETTEXT_PACKAGE=apport
PO_FILES := $(wildcard *.po)
CONTACT=martin.pitt@ubuntu.com
top_srcdir = ..

all: $(DOMAIN).pot

clean:
	rm -rf mo/
	rm -f $(DOMAIN).pot

# update the pot
$(DOMAIN).pot:
	XGETTEXT_ARGS='--msgid-bugs-address=$(CONTACT) --language=python' intltool-update -p

# merge the new stuff into the po files
merge-po: $(PO_FILES) $(DOMAIN.pot)
	XGETTEXT_ARGS='--msgid-bugs-address=$(CONTACT) --language=python' intltool-update -r

# create mo from the pos
%.mo : %.po
	mkdir -p mo/$(subst .po,,$<)/LC_MESSAGES/ 
	msgfmt $< -o mo/$(subst .po,,$<)/LC_MESSAGES/$(DOMAIN).mo 

# generate all *.mo files
build-mo: $(patsubst %.po,%.mo,$(wildcard *.po))
