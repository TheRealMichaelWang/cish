#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"
#include "compiler.h"
#include "file.h"

#define MAGIC_NUM 2187

static const int read_ins(machine_ins_t* output, FILE* infile) {
	uint8_t op_code_buffer;
	ESCAPE_ON_NULL(fread(&op_code_buffer, sizeof(uint8_t), 1, infile));
	output->op_code = op_code_buffer;
	ESCAPE_ON_NULL(fread(&output->a_flag, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fread(&output->b_flag, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fread(&output->c_flag, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fread(&output->a, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fread(&output->b, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fread(&output->c, sizeof(uint16_t), 1, infile));
	return 1;
}

static const int write_ins(machine_ins_t ins, FILE* infile) {
	uint8_t op_code_buffer = ins.op_code;
	ESCAPE_ON_NULL(fwrite(&op_code_buffer, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&ins.a_flag, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&ins.b_flag, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&ins.c_flag, sizeof(uint8_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&ins.a, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&ins.b, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&ins.c, sizeof(uint16_t), 1, infile));
	return 1;
}

static const int read_reg(machine_reg_t* reg, FILE* infile) {
	ESCAPE_ON_NULL(fread(reg, sizeof(uint64_t), 1, infile));
	return 1;
}

static const int write_reg(machine_reg_t reg, FILE* infile) {
	ESCAPE_ON_NULL(fwrite(&reg, sizeof(uint64_t), 1, infile));
	return 1;
}

machine_ins_t* file_load_ins(const char* path, machine_t* machine, uint16_t* instruction_count) {
	FILE* infile = fopen(path, "rb");
	ESCAPE_ON_NULL(infile);

	uint16_t magic_num, global_allocs, const_allocs;
	ESCAPE_ON_NULL(fread(&magic_num, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(magic_num == MAGIC_NUM);

	ESCAPE_ON_NULL(fread(&global_allocs, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fread(&const_allocs, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fread(instruction_count, sizeof(uint16_t), 1, infile));

	ESCAPE_ON_NULL(init_machine(machine, UINT16_MAX, 1000, 1000));
	machine_ins_t* instructions = malloc(*instruction_count * sizeof(machine_ins_t));
	ESCAPE_ON_NULL(instructions);

	for (uint_fast16_t i = 0; i < const_allocs; i++)
		ESCAPE_ON_NULL(read_reg(&machine->stack[global_allocs + i], infile));

	for (uint_fast16_t i = 0; i < *instruction_count; i++)
		ESCAPE_ON_NULL(read_ins(&instructions[i], infile));

	fclose(infile);
	return instructions;
}

const int file_save_compiled(const char* path, compiler_t* compiler, machine_t* machine, machine_ins_t* instructions, uint16_t instruction_count){
	FILE* infile = fopen(path, "wb+");
	ESCAPE_ON_NULL(infile);

	uint16_t magic_num = MAGIC_NUM; 
	ESCAPE_ON_NULL(fwrite(&magic_num, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&compiler->allocated_globals, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&compiler->allocated_constants, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_NULL(fwrite(&instruction_count, sizeof(uint16_t), 1, infile));
	
	for (uint_fast16_t i = 0; i < compiler->allocated_constants; i++)
		ESCAPE_ON_NULL(write_reg(machine->stack[compiler->allocated_globals + i], infile));

	for (uint_fast16_t i = 0; i < instruction_count; i++)
		ESCAPE_ON_NULL(write_ins(instructions[i], infile));
	fclose(infile);
	return 1;
}

char* file_read_source(const char* path) {
	FILE* infile = fopen(path, "rb");
	ESCAPE_ON_NULL(infile);

	fseek(infile, 0, SEEK_END);
	long size = ftell(infile);
	fseek(infile, 0, SEEK_SET);

	char* buffer = malloc((size + 1) * sizeof(char));
	ESCAPE_ON_NULL(buffer);

	ESCAPE_ON_NULL(fread(buffer, sizeof(char), size, infile));
	buffer[size] = 0;

	fclose(infile);

	return buffer;
}