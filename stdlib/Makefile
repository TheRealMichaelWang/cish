define newline


endef

C_OBJS := $(notdir $(wildcard bin/*.o))

all:
	@mkdir -p bin
	$(foreach C_OBJ, $(C_OBJS), gcc bin/$(C_OBJ) superforth.o -lm -shared -o bin/$(C_OBJ).so $(newline))
