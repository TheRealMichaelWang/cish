define newline


endef

C_SOURCES := $(notdir $(wildcard src/*.c))

all:
	$(foreach C_SOURCE, $(C_SOURCES), gcc src/$(C_SOURCE) -o bin/$(C_SOURCE).o -c -Ofast -lm$(newline))
	gcc -o superforth $(wildcard bin/*.c.o) -Ofast -lm

fook:
	$(foreach C_SOURCE, $(C_SOURCES), gcc src/$(C_SOURCE) -o bin/$(C_SOURCE).o -c -g -ggdb -lm$(newline))
	gcc -o superforth $(wildcard bin/*.c.o) -g -ggdb -lm
