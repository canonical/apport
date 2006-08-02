
DOMAIN=apport
PO_FILES := $(wildcard *.po)
CONTACT=martin.pitt@ubuntu.com

all: $(DOMAIN).pot

clean:
	rm -rf mo/
	rm -f $(DOMAIN).pot

# update the pot
$(DOMAIN).pot:
	XGETTEXT_ARGS=--msgid-bugs-address=$(CONTACT) intltool-update -p -g $(DOMAIN)

# merge the new stuff into the po files
merge-po: $(PO_FILES) $(DOMAIN.pot)
	XGETTEXT_ARGS=--msgid-bugs-address=$(CONTACT) intltool-update -r -g $(DOMAIN)

# create mo from the pos
%.mo : %.po
	mkdir -p mo/$(subst .po,,$<)/LC_MESSAGES/ 
	msgfmt $< -o mo/$(subst .po,,$<)/LC_MESSAGES/$(DOMAIN).mo 

# generate all *.mo files
build-mo: $(patsubst %.po,%.mo,$(wildcard *.po))
