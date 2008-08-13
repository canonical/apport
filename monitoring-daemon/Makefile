CC        = gcc
BIN_NAME  = apport-monitor

SOURCES = main.c

shandler: $(SOURCES)
	$(CC) -o $(BIN_NAME) $(SOURCES)

.PHONY: clean
clean:
	-rm -f *.o $(BIN_NAME) *~
