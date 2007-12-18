top_srcdir = ..

all: apport-qt.desktop apport-qt-mime.desktop apport-qt-mimelnk.desktop

%.desktop : %.desktop.in
	intltool-merge -d ${top_srcdir}/po/ $< $@

clean:
	rm -f *.desktop
