.SUFFIXES: .tex .pdf

pdfs=$(subst .tex,.pdf,$(wildcard *.tex))

all: $(pdfs)

.tex.pdf:
	# build it twice to get correct TOC
	pdflatex $< >/dev/null
	pdflatex $< >/dev/null

clean:
	rm -f *.aux *.toc *.log $(pdfs)

.PHONY: all clean
