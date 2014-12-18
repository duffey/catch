CFLAGS = -g3 -pedantic -ansi -Wall -Os -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE \
	$$(curl-config --cflags) $$(xml2-config --cflags)
LDLIBS = $$(curl-config --libs) $$(xml2-config --libs)

catch: catch.o

.PHONY: clean
clean:
	rm catch catch.o
