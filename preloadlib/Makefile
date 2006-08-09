CFLAGS= -g -Wall -W -fPIC

LIBNAME=crashrep
LIB=lib$(LIBNAME).so

ifeq ($(CRASHREPPATH),)
CRASHREPPATH=./apport
endif

$(LIB): lib$(LIBNAME).c
	$(CC) $(CFLAGS) -DCRASHREPPATH=\"$(CRASHREPPATH)\" -shared $^ -o $@

clean:
	rm -f *.o $(LIB)
