CC=gcc
CFLAGS=-g -Wall -pthread -lcrypto -lssl -DDEBUG

SRC=src
COMMONSRCS=$(wildcard $(SRC)/*.c)
SVRSRC=$(SRC)/svr
SVRSRCS=$(wildcard $(SVRSRC)/*.c)
CLISRC=$(SRC)/cli
CLISRCS=$(wildcard $(CLISRC)/*.c)

OBJ=obj
COMMONOBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(COMMONSRCS))
SVROBJ=$(OBJ)/svr
SVROBJS=$(patsubst $(SVRSRC)/%.c, $(SVROBJ)/%.o, $(SVRSRCS))
CLIOBJ=$(OBJ)/cli
CLIOBJS=$(patsubst $(CLISRC)/%.c, $(CLIOBJ)/%.o, $(CLISRCS))

BINDIR=bin
SVRBIN=$(BINDIR)/cspauthd
CLIBIN=$(BINDIR)/cspauth


all: $(SVRBIN) $(CLIBIN)

server: $(SVRBIN)

client: $(CLIBIN)


release: CFLAGS=-pthread -Wall -lcrypto -lssl -O2 -DNDEBUG
release: clean
release: $(SVRBIN) $(CLIBIN)


$(OBJ):
	mkdir $(OBJ)

$(SVROBJ): $(OBJ)
	mkdir $(SVROBJ)

$(CLIOBJ): $(OBJ)
	mkdir $(CLIOBJ)

$(BINDIR):
	mkdir $(BINDIR)

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


$(SVRBIN): $(BINDIR) $(SVROBJ) $(COMMONOBJS) $(SVROBJS)
	-rm $(SVRBIN)
	$(CC) $(CFLAGS) $(COMMONOBJS) $(SVROBJS) -o $@

$(SVROBJ)/%.o: $(SVRSRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


$(CLIBIN): $(BINDIR) $(CLIOBJ) $(COMMONOBJS) $(CLIOBJS)
	-rm $(CLIBIN)
	$(CC) $(CFLAGS) $(COMMONOBJS) $(CLIOBJS) -o $@

$(CLIOBJ)/%.o: $(CLISRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	-rm -r $(BINDIR)/* $(SVROBJ)/* $(CLIOBJ)/* $(OBJ)/*
	-mkdir $(SVROBJ) $(CLIOBJ)
