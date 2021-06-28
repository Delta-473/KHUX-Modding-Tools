#-*-makefile-*-

TARGETS = \
    KHUXdecryptor

all All: $(TARGETS)

################################################################################
INCPATH = -I/usr/local/include
LIBPATH = -L. -L/lib/x86_64-linux-gnu
LIBS = -zlib1 
DEBUGFLAGS = -g
CFLAGS = -Wall -D_FILE_OFFSET_BITS=64 -std=c99 $(DEBUGFLAGS) $(INCPATH)

SRCS = \
	khuxdecrypt3.c chacha.c lodepng.c miniz.c decode_btf.c export_image.c

OBJS = $(SRCS:.c=.o)

.SUFFIXES:	.c

.c.o:	
	cc -c $< $(CFLAGS)


KHUXdecryptor:  clean $(OBJS)
	LDOPTS= \
	cc -o KHUXdecryptor $(CFLAGS) $(OBJS) $(LIBPATH) $(LIBS) 

clean:
	rm -f KHUXdecryptor $(OBJS) core

debug: KHUXdecryptor
	gdb KHUXdecryptor