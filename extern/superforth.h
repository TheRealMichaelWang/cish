/*
* SUPERFORTH
* Writen By Michael Wang
* 
* Use this file to interact with SuperForth
*/

#pragma once

#ifndef SUPERFORTH_H
#define SUPERFORTH_H

#include <stdint.h>

#define SUPERFORTH_ENTRY(BODY) __declspec(dllexport) int superforth_entry(machine_t* machine) BODY

typedef union machine_register machine_reg_t;
typedef struct machine machine_t;

typedef enum gc_trace_mode {
	GC_TRACE_MODE_NONE,
	GC_TRACE_MODE_ALL,
	GC_TRACE_MODE_SOME
} gc_trace_mode_t;

typedef struct machine_heap_alloc {
	machine_reg_t* registers;
	int* init_stat, * trace_stat;
	uint16_t limit;

	int gc_flag, reg_with_table, pre_freed;

	gc_trace_mode_t trace_mode;
} heap_alloc_t; 

typedef union machine_register {
	heap_alloc_t* heap_alloc;
	int64_t long_int;
	double float_int;
	char char_int;
	int bool_flag;
} machine_reg_t;

typedef int (*foreign_func)(machine_t* machine, machine_reg_t* input, machine_reg_t* output);

typedef struct foreign_func_table {
	foreign_func* func_table;
	uint16_t func_count, func_alloc;
} ffi_t;

typedef struct machine {
	machine_reg_t* stack;

	void** positions;

	heap_alloc_t** heap_allocs;
	uint16_t* heap_frame_bounds;

	heap_alloc_t** heap_traces;
	uint16_t* trace_frame_bounds;

	heap_alloc_t** freed_heap_allocs;

	enum error {
		ERROR_NONE,
		ERROR_MEMORY,
		ERROR_INTERNAL,

		//syntax errors
		ERROR_UNEXPECTED_TOK,

		ERROR_READONLY,
		ERROR_TYPE_NOT_ALLOWED,

		ERROR_EXPECTED_SUB_TYPES,

		ERROR_UNDECLARED,
		ERROR_REDECLARATION,

		ERROR_UNEXPECTED_TYPE,
		ERROR_UNEXPECTED_ARGUMENT_SIZE,

		ERROR_CANNOT_RETURN,
		ERROR_CANNOT_CONTINUE,
		ERROR_CANNOT_BREAK,

		//virtual-machine errors
		ERROR_INDEX_OUT_OF_RANGE,
		ERROR_DIVIDE_BY_ZERO,
		ERROR_STACK_OVERFLOW,
		ERROR_READ_UNINIT,

		ERROR_UNRETURNED_FUNCTION,

		ERROR_ABORT,
		ERROR_FOREIGN,

		ERROR_CANNOT_OPEN_FILE
	} last_err;
	
	uint16_t global_offset, position_count, heap_frame, frame_limit, heap_count, heap_alloc_limit, trace_count, trace_alloc_limit, freed_heap_count, alloc_freed_heaps;

	ffi_t ffi_table;
	void* dynamic_library_table;
} machine_t;

int ffi_include_func(ffi_t* ffi_table, foreign_func func);

heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, gc_trace_mode_t trace_mode);
int free_alloc(machine_t* machine, heap_alloc_t* heap_alloc);

#endif // !SUPERFORTH_H