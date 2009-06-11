top_srcdir = ..

all: apport-kde.desktop apport-kde-mime.desktop apport-kde-mimelnk.desktop

%.desktop : %.desktop.in
	intltool-merge -d ${top_srcdir}/po/ $< $@

clean:
	rm -f *.desktop
