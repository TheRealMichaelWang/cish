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

typedef struct compiler_reg {
	uint16_t reg;
	int offset;
} compiler_reg_t;

typedef struct compiler {
	compiler_reg_t* eval_regs;
	int* move_eval;

	compiler_reg_t* var_regs;

	uint16_t* proc_call_offsets;

	ast_t* ast;
	machine_t* target_machine;

	ins_builder_t ins_builder;

	uint16_t current_constant, current_global;
	
	error_t last_err;
} compiler_t;

int init_ins_builder(ins_builder_t* ins_builder);
int ins_builder_append_ins(ins_builder_t* ins_builder, machine_ins_t ins);

int compile(compiler_t* compiler, machine_t* target_machine, ast_t* ast);

#endif // !COMPILER_H
