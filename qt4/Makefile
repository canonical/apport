top_srcdir = ..

all: apport-qt.desktop

%.desktop : %.desktop.in
	intltool-merge -d ${top_srcdir}/po/ $< $@

clean:
	rm -f *.desktop
