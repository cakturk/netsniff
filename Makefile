CFLAGS = -g3 -O2 -Wall -pipe
OBJECTS = program_options.o pcaptest.o
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

$(PROGRAM): $(OBJECTS)
	$(E_LD)$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJECTS) $(LDLIBS)

.PHONY: clean
clean:
	-$(RM) $(PROGRAM) $(OBJECTS) *~ core.*
