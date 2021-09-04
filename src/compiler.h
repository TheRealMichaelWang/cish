#pragma once

#ifndef COMPILER_H
#define COMPILER_H

#include "error.h"
#include "ast.h"
#include "machine.h"

typedef struct ins_builder {
	machine_ins_t* instructions;
	uint16_t instruction_count, alloced_ins;
} ins_builder_t;

typedef struct compiler {
	ast_t ast;
	error_t last_err;
	uint16_t allocated_globals, allocated_constants;
} compiler_t;

const int init_ins_builder(ins_builder_t* ins_builder);
const int ins_builder_append_ins(ins_builder_t* ins_builder, machine_ins_t ins);

const int init_compiler(compiler_t* compiler, const char* source);
void free_compiler(compiler_t* compiler);

const int compile(compiler_t* compiler, machine_t* machine, machine_ins_t** output_ins, uint16_t* output_count);

#endif // !COMPILER_H
