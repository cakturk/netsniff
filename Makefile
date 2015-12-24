CFLAGS = -g3 -O0 -Wall -pipe
OBJECTS = program_options.o netsniff.o
PROGRAM = pcaptest
LDLIBS = -lpcap

ifndef ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	E_CC	= @echo ' CC    '$@;
	E_LD	= @echo ' LD    '$@;
endif
endif

all: $(PROGRAM)

%.o: %.c
	$(E_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

program_options.o: program_options.c netsniff.h
	$(E_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(PROGRAM): $(OBJECTS)
	$(E_LD)$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJECTS) $(LDLIBS)

.PHONY: clean
clean:
	-$(RM) $(PROGRAM) $(OBJECTS) *~ core.*
