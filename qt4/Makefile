top_srcdir = ..

all: apport-qt4.desktop

%.desktop : %.desktop.in
	intltool-merge -d ${top_srcdir}/po/ $< $@

clean:
	rm -f *.desktop
