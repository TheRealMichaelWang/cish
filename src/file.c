#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"
#include "compiler.h"
#include "file.h"

#define MAGIC_NUM 4269
#define _CRT_SECURE_NO_WARNINGS

static int read_ins(machine_ins_t* output, FILE* infile) {
	uint16_t op_code_buffer;
	ESCAPE_ON_FAIL(fread(&op_code_buffer, sizeof(uint16_t), 1, infile));
	output->op_code = op_code_buffer;
	ESCAPE_ON_FAIL(fread(&output->a, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fread(&output->b, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fread(&output->c, sizeof(uint16_t), 1, infile));
	return 1;
}

static int read_type_sig(machine_type_sig_t* out_sig, FILE* infile) {
	ESCAPE_ON_FAIL(fread(&out_sig->super_signature, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fread(&out_sig->sub_type_count, sizeof(uint16_t), 1, infile));

	ESCAPE_ON_FAIL(out_sig->sub_types = malloc(out_sig->sub_type_count * sizeof(machine_type_sig_t)));

	if (out_sig->super_signature != TYPE_TYPEARG) {
		for (uint_fast8_t i = 0; i < out_sig->sub_type_count; i++)
			ESCAPE_ON_FAIL(read_type_sig(&out_sig->sub_types[i], infile));
	}
	return 1;
}

static int write_ins(machine_ins_t ins, FILE* infile) {
	uint16_t op_code_buffer = ins.op_code;
	ESCAPE_ON_FAIL(fwrite(&op_code_buffer, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&ins.a, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&ins.b, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&ins.c, sizeof(uint16_t), 1, infile));
	return 1;
}

static int write_type_sig(machine_type_sig_t type_sig, FILE* infile) {
	ESCAPE_ON_FAIL(fwrite(&type_sig.super_signature, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&type_sig.sub_type_count, sizeof(uint16_t), 1, infile));
	if (type_sig.super_signature != TYPE_TYPEARG) {
		for (uint_fast8_t i = 0; i < type_sig.sub_type_count; i++)
			ESCAPE_ON_FAIL(write_type_sig(type_sig.sub_types[i], infile));
	}
	return 1;
}

machine_ins_t* file_load_ins(const char* path, machine_t* machine, uint16_t* instruction_count, uint16_t* constant_count, uint16_t* signature_count) {
	FILE* infile = fopen(path, "rb");
	ESCAPE_ON_FAIL(infile);

	uint16_t magic_num, const_allocs, type_table_count, defined_sigs;
	ESCAPE_ON_FAIL(fread(&magic_num, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(magic_num == MAGIC_NUM);

	ESCAPE_ON_FAIL(fread(&const_allocs, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fread(&type_table_count, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fread(&defined_sigs, sizeof(uint16_t), 1, infile));

	ESCAPE_ON_FAIL(fread(instruction_count, sizeof(uint16_t), 1, infile));

	ESCAPE_ON_FAIL(init_machine(machine, UINT16_MAX / 8, 1000, type_table_count));
	machine_ins_t* instructions = malloc(*instruction_count * sizeof(machine_ins_t));
	ESCAPE_ON_FAIL(instructions);

	if (constant_count)
		*constant_count = const_allocs;
	if (signature_count)
		*signature_count = defined_sigs;

	for (uint_fast16_t i = 0; i < const_allocs; i++)
		ESCAPE_ON_FAIL(fread(&machine->stack[i], sizeof(uint64_t), 1, infile));

	for (uint_fast8_t i = 0; i < defined_sigs; i++) {
		machine_type_sig_t* loaded_sig = new_type_sig(machine);
		ESCAPE_ON_FAIL(loaded_sig);
		ESCAPE_ON_FAIL(read_type_sig(loaded_sig, infile));
	}
	
	ESCAPE_ON_FAIL(fread(machine->type_table, sizeof(uint16_t), type_table_count, infile));

	for (uint_fast16_t i = 0; i < *instruction_count; i++)
		ESCAPE_ON_FAIL(read_ins(&instructions[i], infile));

	fclose(infile);
	return instructions;
}

int file_save_compiled(const char* path, ast_t* ast, machine_t* machine, machine_ins_t* instructions, uint16_t instruction_count) {
	FILE* infile = fopen(path, "wb+");
	ESCAPE_ON_FAIL(infile);

	uint16_t magic_num = MAGIC_NUM;
	ESCAPE_ON_FAIL(fwrite(&magic_num, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&ast->constant_count, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&ast->record_count, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&machine->defined_sig_count, sizeof(uint16_t), 1, infile));
	ESCAPE_ON_FAIL(fwrite(&instruction_count, sizeof(uint16_t), 1, infile));

	for (uint_fast16_t i = 0; i < ast->constant_count; i++)
		ESCAPE_ON_FAIL(fwrite(&machine->stack[i], sizeof(uint64_t), 1, infile));
	for (uint_fast16_t i = 0; i < machine->defined_sig_count; i++)
		ESCAPE_ON_FAIL(write_type_sig(machine->defined_signatures[i], infile));
	ESCAPE_ON_FAIL(fwrite(machine->type_table, sizeof(uint16_t), ast->record_count, infile));

	for (uint_fast16_t i = 0; i < instruction_count; i++)
		ESCAPE_ON_FAIL(write_ins(instructions[i], infile));
	fclose(infile);
	return 1;
}

char* file_read_source(const char* path) {
	FILE* infile = fopen(path, "rb");
	ESCAPE_ON_FAIL(infile);

	fseek(infile, 0, SEEK_END);
	long size = ftell(infile);
	fseek(infile, 0, SEEK_SET);

	char* buffer = malloc((size + 1) * sizeof(char));
	ESCAPE_ON_FAIL(buffer);

	ESCAPE_ON_FAIL(fread(buffer, sizeof(char), size, infile));
	if (size >= 3 && (unsigned char)buffer[0] == 0xEF && (unsigned char)buffer[1] == 0xBB && (unsigned char)buffer[2] == 0xBF) { //bom-detection
		size -= 3;
		memcpy(buffer, buffer + 3, size);
	}

	buffer[size] = 0;

	fclose(infile);

	return buffer;
}