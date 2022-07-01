define newline


endef

C_SOURCES := $(notdir $(wildcard src/*.c))

all:
	@mkdir -p bin
	$(foreach C_SOURCE, $(C_SOURCES), gcc src/$(C_SOURCE) -o bin/$(C_SOURCE).o -c -Ofast$(newline))
	gcc -o cish $(wildcard bin/*.c.o) -Ofast -lm -ldl

fook:
	@mkdir -p bin
	$(foreach C_SOURCE, $(C_SOURCES), gcc src/$(C_SOURCE) -o bin/$(C_SOURCE).o -c -g -ggdb -Wall$(newline))
	gcc -o cish $(wildcard bin/*.c.o) -g -ggdb -lm -ldl
