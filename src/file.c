#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"
#include "compiler.h"
#include "file.h"

#define READ(SIZE) *(current_src += SIZE)
#define WRITE(SIZE) 

static const char* read_ins(machine_ins_t* output, char* current_src) {
	output->op_code = READ(sizeof(uint8_t));
	output->a_flag = READ(sizeof(uint8_t));
	output->b_flag = READ(sizeof(uint8_t));
	output->c_flag = READ(sizeof(uint8_t));

	output->a = READ(sizeof(uint64_t));
	output->b = READ(sizeof(uint64_t));
	output->c = READ(sizeof(uint64_t));
	return current_src;
}

static const char* write_ins(machine_ins_t ins, char* output_src) {

}

static const char* read_reg(register_t* reg, char* current_src) {
	memcpy(reg, current_src += sizeof(uint64_t), sizeof(uint64_t));
	return current_src;
}

const int file_read_ins(const char* path, machine_t* machine, machine_ins_t** output_ins, uint64_t* output_count) {
	FILE* infile = fopen(path, "rb");
	ESCAPE_ON_NULL(infile);

	fseek(infile, 0, SEEK_END);
	long size = ftell(infile);
	fseek(infile, 0, SEEK_SET);

	char* current_src = malloc((size_t)size + 1);
	char* tofree = current_src;
	ESCAPE_ON_NULL(current_src);
	
	fread(current_src, sizeof(char), size, infile);
	current_src[size] = 0;

	uint32_t alloced_globals = READ(sizeof(uint32_t));
	uint32_t alloced_consts = READ(sizeof(uint32_t));

	ESCAPE_ON_NULL(init_machine(machine, UINT16_MAX, 1000, 1000));

	for (uint_fast32_t i = 0; i < alloced_consts; i++)
		current_src = read_reg(&machine->stack[alloced_globals + i], current_src);

	ins_builder_t ins_builder;
	ESCAPE_ON_NULL(init_ins_builder(&ins_builder));

	while (*current_src)
	{
		machine_ins_t ins;
		current_src = read_ins(&ins, current_src);
		ins_builder_append_ins(&ins_builder, ins);
	}
	*output_ins = ins_builder.instructions;
	*output_count = ins_builder.instruction_count;

	free(tofree);
	fclose(infile);
	return 1;
}