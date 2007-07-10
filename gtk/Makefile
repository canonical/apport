top_srcdir = ..

all: apport-gtk.desktop apport-gtk-mime.desktop

%.desktop : %.desktop.in
	intltool-merge -d ${top_srcdir}/po/ $< $@

clean:
	rm -f *.desktop
