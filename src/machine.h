#pragma once

#ifndef OPCODE_H
#define OPCODE_H

#include <stdint.h>
#include "error.h"
#include "ffi.h"

typedef union machine_register machine_reg_t;

typedef enum machine_op_code {
	OP_CODE_ABORT,
	OP_CODE_FOREIGN,

	OP_CODE_MOVE,

	OP_CODE_JUMP,
	OP_CODE_JUMP_CHECK,

	OP_CODE_CALL,
	OP_CODE_RETURN,
	OP_CODE_LABEL,

	OP_CODE_LOAD_HEAP,
	OP_CODE_LOAD_HEAP_I,
	OP_CODE_LOAD_HEAP_I_BOUND,
	OP_CODE_STORE_HEAP,
	OP_CODE_STORE_HEAP_I,
	OP_CODE_STORE_HEAP_I_BOUND,
	OP_CODE_HEAP_TRACE_I,

	OP_CODE_STACK_OFFSET,
	OP_CODE_STACK_DEOFFSET,

	OP_CODE_HEAP_ALLOC,
	OP_CODE_HEAP_ALLOC_I,

	OP_CODE_HEAP_NEW_FRAME,
	OP_CODE_HEAP_TRACE,
	OP_CODE_HEAP_CLEAN,

	OP_CODE_AND,
	OP_CODE_OR,
	OP_CODE_NOT,
	OP_CODE_LENGTH,
	
	OP_CODE_BOOL_EQUAL,
	OP_CODE_CHAR_EQUAL,
	OP_CODE_LONG_EQUAL,
	OP_CODE_FLOAT_EQUAL,

	OP_CODE_LONG_MORE,
	OP_CODE_LONG_LESS,
	OP_CODE_LONG_MORE_EQUAL,
	OP_CODE_LONG_LESS_EQUAL,

	OP_CODE_LONG_ADD,
	OP_CODE_LONG_SUBRACT,
	OP_CODE_LONG_MULTIPLY,
	OP_CODE_LONG_DIVIDE,
	OP_CODE_LONG_MODULO,
	OP_CODE_LONG_EXPONENTIATE,

	OP_CODE_FLOAT_MORE,
	OP_CODE_FLOAT_LESS,
	OP_CODE_FLOAT_MORE_EQUAL,
	OP_CODE_FLOAT_LESS_EQUAL,

	OP_CODE_FLOAT_ADD,
	OP_CODE_FLOAT_SUBTRACT,
	OP_CODE_FLOAT_MULTIPLY,
	OP_CODE_FLOAT_DIVIDE,
	OP_CODE_FLOAT_MODULO,
	OP_CODE_FLOAT_EXPONENTIATE,

	OP_CODE_LONG_NEGATE,
	OP_CODE_FLOAT_NEGATE
} op_code_t;

typedef enum gc_trace_mode {
	GC_NO_TRACE,
	GC_TRACE_ALL,
	GC_TRACE_SOME
} gc_trace_mode_t;

typedef struct machine_instruction {
	op_code_t op_code;
	uint16_t a, b, c;
	uint8_t a_flag, b_flag, c_flag;
} machine_ins_t;

typedef struct machine_heap_alloc {
	machine_reg_t* registers;
	int* init_stat, *trace_stat;
	uint16_t limit;

	int gc_flag;
	gc_trace_mode_t trace_mode;
} heap_alloc_t;

typedef union machine_register {
	heap_alloc_t* heap_alloc;
	int64_t long_int;
	double float_int;
	char char_int;
	int bool_flag;
	machine_ins_t* ip;
} machine_reg_t;

typedef struct machine {
	machine_reg_t* stack;

	machine_ins_t** positions;

	heap_alloc_t** heap_allocs;
	uint16_t* heap_frame_bounds;

	heap_alloc_t** heap_traces;
	uint16_t* trace_frame_bounds;

	error_t last_err;
	
	uint16_t global_offset, position_count, heap_frame, frame_limit, heap_count, heap_alloc_limit, trace_count, trace_alloc_limit;

	ffi_t ffi_table;
} machine_t;

int init_machine(machine_t* machine, uint16_t stack_size, uint16_t heap_alloc_limit, uint16_t frame_limit);
void free_machine(machine_t* machine);

int machine_execute(machine_t* machine, machine_ins_t* instructions);

heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, gc_trace_mode_t trace_mode);
#endif // !OPCODE_H