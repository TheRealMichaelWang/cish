#pragma once

#ifndef COMPILER_H
#define COMPILER_H

#include "error.h"
#include "ast.h"
#include "machine.h"

typedef struct compiler_reg {
	uint16_t reg;
	int offset;
} compiler_reg_t;

typedef enum compiler_op_code {
	COMPILER_OP_CODE_ABORT,
	COMPILER_OP_CODE_FOREIGN,

	COMPILER_OP_CODE_MOVE,
	COMPILER_OP_CODE_SET,

	COMPILER_OP_CODE_JUMP,
	COMPILER_OP_CODE_JUMP_CHECK,

	COMPILER_OP_CODE_CALL,
	COMPILER_OP_CODE_RETURN,
	COMPILER_OP_CODE_LABEL,

	COMPILER_OP_CODE_LOAD_ALLOC,
	COMPILER_OP_CODE_LOAD_ALLOC_I,
	COMPILER_OP_CODE_LOAD_ALLOC_I_BOUND,
	COMPILER_OP_CODE_STORE_ALLOC,
	COMPILER_OP_CODE_STORE_ALLOC_I,
	COMPILER_OP_CODE_STORE_ALLOC_I_BOUND,
	COMPILER_OP_CODE_CONF_TRACE,
	COMPILER_OP_CODE_DYNAMIC_CONF,
	COMPILER_OP_CODE_DYNAMIC_CONF_ALL,

	COMPILER_OP_CODE_STACK_OFFSET,
	COMPILER_OP_CODE_STACK_DEOFFSET,

	COMPILER_OP_CODE_ALLOC,
	COMPILER_OP_CODE_ALLOC_I,

	COMPILER_OP_CODE_FREE,
	COMPILER_OP_CODE_DYNAMIC_FREE,

	COMPILER_OP_CODE_GC_NEW_FRAME,
	COMPILER_OP_CODE_GC_TRACE,
	COMPILER_OP_CODE_DYNAMIC_TRACE,
	COMPILER_OP_CODE_GC_CLEAN,

	COMPILER_OP_CODE_AND,
	COMPILER_OP_CODE_OR,
	COMPILER_OP_CODE_NOT,
	COMPILER_OP_CODE_LENGTH,

  COMPILER_OP_CODE_PTR_EQUAL,
	COMPILER_OP_CODE_BOOL_EQUAL,
	COMPILER_OP_CODE_CHAR_EQUAL,
	COMPILER_OP_CODE_LONG_EQUAL,
	COMPILER_OP_CODE_FLOAT_EQUAL,

	COMPILER_OP_CODE_LONG_MORE,
	COMPILER_OP_CODE_LONG_LESS,
	COMPILER_OP_CODE_LONG_MORE_EQUAL,
	COMPILER_OP_CODE_LONG_LESS_EQUAL,

	COMPILER_OP_CODE_LONG_ADD,
	COMPILER_OP_CODE_LONG_SUBRACT,
	COMPILER_OP_CODE_LONG_MULTIPLY,
	COMPILER_OP_CODE_LONG_DIVIDE,
	COMPILER_OP_CODE_LONG_MODULO,
	COMPILER_OP_CODE_LONG_EXPONENTIATE,

	COMPILER_OP_CODE_FLOAT_MORE,
	COMPILER_OP_CODE_FLOAT_LESS,
	COMPILER_OP_CODE_FLOAT_MORE_EQUAL,
	COMPILER_OP_CODE_FLOAT_LESS_EQUAL,

	COMPILER_OP_CODE_FLOAT_ADD,
	COMPILER_OP_CODE_FLOAT_SUBTRACT,
	COMPILER_OP_CODE_FLOAT_MULTIPLY,
	COMPILER_OP_CODE_FLOAT_DIVIDE,
	COMPILER_OP_CODE_FLOAT_MODULO,
	COMPILER_OP_CODE_FLOAT_EXPONENTIATE,

	COMPILER_OP_CODE_LONG_NEGATE,
	COMPILER_OP_CODE_FLOAT_NEGATE,

	COMPILER_OP_CODE_TYPE_RELATE,
	COMPILER_OP_CODE_CONFIG_TYPESIG,
	COMPILER_OP_CODE_RUNTIME_TYPECHECK,
	COMPILER_OP_CODE_RUNTIME_TYPECAST
} compiler_op_code_t;

typedef struct compiler_ins {
	compiler_op_code_t op_code;
	compiler_reg_t regs[3];
} compiler_ins_t;

typedef struct ins_builder {
	compiler_ins_t* instructions;
	uint16_t instruction_count, alloced_ins;
} ins_builder_t;

typedef struct compiler {
	compiler_reg_t* eval_regs;
	int* move_eval;
	uint16_t* eval_defed_sigs;

	compiler_reg_t* var_regs;

	uint16_t* proc_call_offsets;
	compiler_reg_t** proc_generic_regs;

	ast_t* ast;
	machine_t* target_machine;

	ins_builder_t ins_builder;

	uint16_t current_global, defined_sigs;
	
	error_t last_err;
} compiler_t;

int init_ins_builder(ins_builder_t* ins_builder);
int ins_builder_append_ins(ins_builder_t* ins_builder, compiler_ins_t ins);

int compile(compiler_t* compiler, machine_t* target_machine, ast_t* ast);

void compiler_ins_to_machine_ins(compiler_ins_t* compiler_ins, machine_ins_t* machine_ins, uint64_t ins_count);

int compiler_define_typesig(compiler_t* compiler, typecheck_type_t type);
#endif // !COMPILER_H
