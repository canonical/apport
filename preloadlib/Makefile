CFLAGS= -g -Wall -W -fPIC

LIBNAME=apport
LIB=lib$(LIBNAME).so

ifeq ($(AGENTPATH),)
AGENTPATH=/usr/share/apport/apport
endif

ifneq ($(PIPE_CORE),)
PIPE=-DPIPE_CORE
endif

$(LIB): lib$(LIBNAME).c
	$(CC) $(CFLAGS) -DAGENTPATH=\"$(AGENTPATH)\" $(PIPE) -shared $^ -o $@

clean:
	rm -f *.o $(LIB)
