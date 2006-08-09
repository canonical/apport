CFLAGS= -g -Wall -W -fPIC

LIBNAME=apport
LIB=lib$(LIBNAME).so

ifeq ($(AGENTPATH),)
AGENTPATH=/usr/share/apport/apport
endif

$(LIB): lib$(LIBNAME).c
	$(CC) $(CFLAGS) -DAGENTPATH=\"$(AGENTPATH)\" -shared $^ -o $@

clean:
	rm -f *.o $(LIB)
