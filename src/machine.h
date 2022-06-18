#pragma once

#ifndef OPCODE_H
#define OPCODE_H

#include <stdint.h>
#include "error.h"
#include "ffi.h"

typedef union machine_register machine_reg_t;

typedef enum gc_trace_mode {
	GC_TRACE_MODE_NONE,
	GC_TRACE_MODE_ALL,
	GC_TRACE_MODE_SOME
} gc_trace_mode_t;

#define DECL3OP(OPCODE) MACHINE_OP_CODE_##OPCODE##_LLL,MACHINE_OP_CODE_##OPCODE##_LLG,MACHINE_OP_CODE_##OPCODE##_LGL,MACHINE_OP_CODE_##OPCODE##_LGG,MACHINE_OP_CODE_##OPCODE##_GLL,MACHINE_OP_CODE_##OPCODE##_GLG,MACHINE_OP_CODE_##OPCODE##_GGL, MACHINE_OP_CODE_##OPCODE##_GGG

#define DECL2OP(OPCODE) MACHINE_OP_CODE_##OPCODE##_LL, MACHINE_OP_CODE_##OPCODE##_LG, MACHINE_OP_CODE_##OPCODE##_GL, MACHINE_OP_CODE_##OPCODE##_GG

#define DECL1OP(OPCODE) MACHINE_OP_CODE_##OPCODE##_L, MACHINE_OP_CODE_##OPCODE##_G

typedef enum machine_op_code {
	MACHINE_OP_CODE_ABORT,
	DECL3OP(FOREIGN),
	DECL2OP(MOVE),
	MACHINE_OP_CODE_SET_L,
	MACHINE_OP_CODE_POP_ATOM_TYPESIGS,
	MACHINE_OP_CODE_JUMP,
	DECL1OP(JUMP_CHECK),
	DECL1OP(CALL),
	MACHINE_OP_CODE_RETURN,
	DECL1OP(LABEL),
	DECL3OP(LOAD_ALLOC),
	DECL2OP(LOAD_ALLOC_I),
	DECL2OP(LOAD_ALLOC_I_BOUND),
	DECL3OP(STORE_ALLOC),
	DECL2OP(STORE_ALLOC_I),
	DECL2OP(STORE_ALLOC_I_BOUND),
	DECL1OP(CONF_TRACE),
	MACHINE_OP_CODE_DYNAMIC_CONF_LL,
	MACHINE_OP_CODE_DYNAMIC_CONF_ALL_LL,
	MACHINE_OP_CODE_STACK_OFFSET,
	MACHINE_OP_CODE_STACK_DEOFFSET,
	DECL2OP(ALLOC),
	DECL1OP(ALLOC_I),
	DECL1OP(FREE),
	MACHINE_OP_CODE_DYNAMIC_FREE_LL,
	MACHINE_OP_CODE_GC_NEW_FRAME,
	DECL1OP(GC_TRACE),
	MACHINE_OP_CODE_DYNAMIC_TRACE_LL,
	MACHINE_OP_CODE_GC_CLEAN,
	DECL3OP(AND),
	DECL3OP(OR),
	DECL2OP(NOT),
	DECL2OP(LENGTH),
	DECL3OP(PTR_EQUAL),
	DECL3OP(BOOL_EQUAL),
	DECL3OP(CHAR_EQUAL),
	DECL3OP(LONG_EQUAL),
	DECL3OP(FLOAT_EQUAL),
	DECL3OP(LONG_MORE),
	DECL3OP(LONG_LESS),
	DECL3OP(LONG_MORE_EQUAL),
	DECL3OP(LONG_LESS_EQUAL),
	DECL3OP(LONG_ADD),
	DECL3OP(LONG_SUBTRACT),
	DECL3OP(LONG_MULTIPLY),
	DECL3OP(LONG_DIVIDE),
	DECL3OP(LONG_MODULO),
	DECL3OP(LONG_EXPONENTIATE),
	DECL3OP(FLOAT_MORE),
	DECL3OP(FLOAT_LESS),
	DECL3OP(FLOAT_MORE_EQUAL),
	DECL3OP(FLOAT_LESS_EQUAL),
	DECL3OP(FLOAT_ADD),
	DECL3OP(FLOAT_SUBTRACT),
	DECL3OP(FLOAT_MULTIPLY),
	DECL3OP(FLOAT_DIVIDE),
	DECL3OP(FLOAT_MODULO),
	DECL3OP(FLOAT_EXPONENTIATE),

	DECL2OP(LONG_NEGATE),
	DECL2OP(FLOAT_NEGATE),
	DECL1OP(LONG_INCREMENT),
	DECL1OP(LONG_DECREMENT),
	DECL1OP(FLOAT_INCREMENT),
	DECL1OP(FLOAT_DECREMENT),

	DECL1OP(CONFIG_TYPESIG),
	DECL2OP(RUNTIME_TYPECHECK),
	DECL2OP(RUNTIME_TYPECAST),
	DECL1OP(DYNAMIC_TYPECHECK_DD),
	DECL1OP(DYNAMIC_TYPECHECK_DR),
	DECL1OP(DYNAMIC_TYPECHECK_RD),
	DECL1OP(DYNAMIC_TYPECAST_DD),
	DECL1OP(DYNAMIC_TYPECAST_DR),
	DECL1OP(DYNAMIC_TYPECAST_RD),
} machine_op_code_t;
#undef DECL1OP
#undef DECL2OP
#undef DECL3OP

typedef struct machine_instruction {
	machine_op_code_t op_code;
	uint16_t a, b, c;
} machine_ins_t;

typedef struct machine_type_signature machine_type_sig_t;
typedef struct machine_type_signature {
	uint16_t super_signature;
	machine_type_sig_t* sub_types;
	uint8_t sub_type_count;
} machine_type_sig_t;

typedef struct machine_heap_alloc {
	machine_reg_t* registers;
	int* init_stat, *trace_stat;
	uint16_t limit;

	int gc_flag, reg_with_table, pre_freed;
	gc_trace_mode_t trace_mode;

	machine_type_sig_t* type_sig;
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
	heap_alloc_t** reset_stack;

	heap_alloc_t** freed_heap_allocs;

	uint64_t last_err_ip;
	error_t last_err;
	
	uint16_t global_offset, position_count, heap_frame, frame_limit, 
		heap_count, alloced_heap_allocs, 
		trace_count, alloced_trace_allocs, 
		freed_heap_count, alloc_freed_heaps, 
		reset_count, alloced_reset;

	ffi_t ffi_table;
	dynamic_library_table_t* dynamic_library_table;

	uint16_t* type_table;
	
	machine_type_sig_t* defined_signatures;
	uint16_t defined_sig_count, alloced_sig_defs;
} machine_t;

int init_machine(machine_t* machine, uint16_t stack_size, uint16_t frame_limit, uint16_t type_count);
void free_machine(machine_t* machine);

int machine_execute(machine_t* machine, machine_ins_t* instructions);

heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, gc_trace_mode_t trace_mode);
machine_type_sig_t* new_type_sig(machine_t* machine);
#endif // !OPCODE_H