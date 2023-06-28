COMPILER =/opt/Xilinx/SDK/2017.4/gnu/aarch32/lin/gcc-arm-linux-gnueabi/bin
CC=$(COMPILER)/arm-linux-gnueabihf-gcc
OBJECT=main.o sm4_impl.o
TARGETS=encryptionChip
BUILDAGENTLIBS=-lpthread -lm -Wall -g

all: $(TARGETS)

$(TARGETS): $(OBJECT)
		$(CC) -o $(TARGETS) $(OBJECT)  $(BUILDAGENTLIBS)
		
clean:
	rm $(OBJECT) $(TARGETS)