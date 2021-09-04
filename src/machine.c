#include <stdlib.h>
#include <math.h>
#include "error.h"
#include "machine.h"

static uint64_t longpow(uint64_t base, uint64_t exp) {
	uint64_t result = 1;
	for (;;) {
		if (exp & 1)
			result *= base;
		exp >>= 1;
		if (!exp)
			break;
		base *= base;
	}
	return result;
}

static heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, int trace_children) {
	if (machine->heap_count == machine->heap_alloc_limit)
		PANIC(machine, ERROR_STACK_OVERFLOW);
	heap_alloc_t* heap_alloc = malloc(sizeof(heap_alloc_t));
	PANIC_ON_NULL(heap_alloc, machine, ERROR_MEMORY);
	PANIC_ON_NULL(heap_alloc->registers = malloc(req_size * sizeof(register_t)), machine, ERROR_MEMORY);
	PANIC_ON_NULL(heap_alloc->init_stat = calloc(req_size, sizeof(int)), machine, ERROR_MEMORY);
	heap_alloc->limit = req_size;
	heap_alloc->gc_flag = 0;
	heap_alloc->trace_children = trace_children;
	machine->heap_allocs[machine->heap_count++] = heap_alloc;
	return heap_alloc;
}

static uint16_t machine_heap_trace(machine_t* machine, heap_alloc_t* heap_alloc, heap_alloc_t** reset_stack) {
	uint16_t traced = 1;

	heap_alloc->gc_flag = 1;
	*(reset_stack++) = heap_alloc;

	if (heap_alloc->trace_children)
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if(heap_alloc->init_stat[i])
				traced += machine_heap_trace(machine, heap_alloc->registers[i].heap_alloc, reset_stack);
	return traced;
}

#define AREG ins.a_flag ? ins.a + machine->global_offset : ins.a
#define BREG ins.b_flag ? ins.b + machine->global_offset : ins.b
#define CREG ins.c_flag ? ins.c + machine->global_offset : ins.c

static const int machine_execute_instruction(machine_t* machine, machine_ins_t* instructions) {
	machine_ins_t ins = *machine->ip;

   	switch (ins.op_code)
	{
	case OP_CODE_MOVE:
		machine->stack[AREG] = machine->stack[BREG];
		break;
	case OP_CODE_CHECK:
		if (machine->stack[AREG].bool_flag)
			machine->ip++;
		break;
	case OP_CODE_JUMP:
		machine->ip = &instructions[AREG];
 		return 1;
	case OP_CODE_JUMP_HIST: {
		PANIC_ON_NULL(machine->position_count != machine->frame_limit, machine, ERROR_STACK_OVERFLOW);
		machine->positions[machine->position_count++] = machine->ip;
		machine->ip = machine->stack[AREG].ip;
		return 1;
	}
	case OP_CODE_LABEL:
		machine->stack[AREG].ip = &instructions[BREG];
		break;
	case OP_CODE_JUMP_BACK: {
		machine->ip = machine->positions[--machine->position_count];
		break;
	}
	case OP_CODE_LOAD_HEAP: {
		register_t array_register = machine->stack[AREG];
		register_t index_register = machine->stack[BREG];
		if (index_register.long_int < 0 || index_register.long_int >= array_register.heap_alloc->limit)
			PANIC(machine, ERROR_INDEX_OUT_OF_RANGE);
		if (!array_register.heap_alloc->init_stat[index_register.long_int])
			PANIC(machine, ERROR_READ_UNINIT);
		machine->stack[CREG] = array_register.heap_alloc->registers[index_register.long_int];
		break;
	}
	case OP_CODE_LOAD_HEAP_I: {
		uint16_t a_reg = AREG;
		register_t array_register = machine->stack[a_reg];
		if (!array_register.heap_alloc->init_stat[a_reg])
			PANIC(machine, ERROR_READ_UNINIT);
		machine->stack[CREG] = array_register.heap_alloc->registers[BREG];
		break;
	}
	case OP_CODE_STORE_HEAP: {
		register_t array_register = machine->stack[AREG];
		register_t index_register = machine->stack[BREG];
		if (index_register.long_int < 0 || index_register.long_int >= array_register.heap_alloc->limit)
			PANIC(machine, ERROR_INDEX_OUT_OF_RANGE);
		array_register.heap_alloc->registers[index_register.long_int] = machine->stack[CREG];
		array_register.heap_alloc->init_stat[index_register.long_int] = 1;
		break;
	}
	case OP_CODE_STORE_HEAP_I: {
		uint16_t b_reg = BREG;
		register_t array_register = machine->stack[AREG];
		array_register.heap_alloc->registers[b_reg] = machine->stack[CREG];
		array_register.heap_alloc->init_stat[b_reg] = 1;
		break;
	}
	case OP_CODE_STACK_OFFSET:
		machine->global_offset += ins.a;
		break;
	case OP_CODE_STACK_DEOFFSET:
		machine->global_offset -= ins.a;
		break;
	case OP_CODE_HEAP_ALLOC:
		ESCAPE_ON_NULL(machine->stack[AREG].heap_alloc = machine_alloc(machine, machine->stack[BREG].long_int, ins.c));
		break;
	case OP_CODE_HEAP_ALLOC_I:
		ESCAPE_ON_NULL(machine->stack[AREG].heap_alloc = machine_alloc(machine, ins.b, ins.c));
		break;
	case OP_CODE_HEAP_NEW_FRAME: {
		if (machine->heap_frame == machine->frame_limit)
			PANIC(machine, ERROR_STACK_OVERFLOW);
		machine->heap_frame_bounds[machine->heap_frame] = machine->heap_count;
		machine->heap_reset_bounds[machine->heap_frame++] = machine->heap_reset_count;
		break;
	}
	case OP_CODE_HEAP_TRACE: {
		machine->heap_reset_count += machine_heap_trace(machine, machine->stack[AREG].heap_alloc, &machine->heap_reset_stack[machine->heap_reset_count]);
		break;
	}
	case OP_CODE_HEAP_CLEAN: {
		uint16_t kept_allocs = 0;
		uint16_t bound_start = machine->heap_frame_bounds[--machine->heap_frame];
		for(uint_fast16_t i = bound_start; i < machine->heap_count; i++)
			if ((*machine->heap_allocs[i]).gc_flag)
				machine->heap_allocs[bound_start + kept_allocs++] = machine->heap_allocs[i];
			else {
				free(machine->heap_allocs[i]->registers);
				free(machine->heap_allocs[i]->init_stat);
				free(machine->heap_allocs[i]);
			}
		machine->heap_count = bound_start + kept_allocs;
		for (uint_fast16_t i = machine->heap_reset_bounds[machine->heap_frame]; i < machine->heap_reset_count; i++)
			machine->heap_reset_stack[i]->gc_flag = 0;
		machine->heap_reset_count = machine->heap_reset_bounds[machine->heap_frame];
		break;
	}
	case OP_CODE_AND:
		machine->stack[CREG].bool_flag = machine->stack[AREG].bool_flag && machine->stack[BREG].bool_flag;
		break;
	case OP_CODE_OR:
		machine->stack[CREG].bool_flag = machine->stack[AREG].bool_flag || machine->stack[BREG].bool_flag;
		break;
	case OP_CODE_NOT:
		machine->stack[BREG].bool_flag = !machine->stack[AREG].bool_flag;
		break;
	case OP_CODE_BOOL_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].bool_flag == machine->stack[BREG].bool_flag;
		break;
	case OP_CODE_CHAR_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].char_int == machine->stack[BREG].char_int;
		break;
	case OP_CODE_LONG_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].long_int == machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_MORE_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].long_int >= machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_LESS_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].long_int <= machine->stack[BREG].long_int;
		break;
	case OP_CODE_FLOAT_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].float_int == machine->stack[BREG].float_int;
		break;
	case OP_CODE_FLOAT_MORE_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].float_int >= machine->stack[BREG].float_int;
		break;
	case OP_CODE_FLOAT_LESS_EQUAL:
		machine->stack[CREG].bool_flag = machine->stack[AREG].float_int <= machine->stack[BREG].float_int;
		break;
	case OP_CODE_LONG_MORE:
		machine->stack[CREG].bool_flag = machine->stack[AREG].long_int > machine->stack[BREG].long_int;
		break;
	case OP_CODE_FLOAT_MORE:
		machine->stack[CREG].bool_flag = machine->stack[AREG].float_int > machine->stack[BREG].float_int;
		break;
	case OP_CODE_LONG_LESS:
		machine->stack[CREG].bool_flag = machine->stack[AREG].long_int < machine->stack[BREG].long_int;
		break;
	case OP_CODE_FLOAT_LESS:
		machine->stack[CREG].bool_flag = machine->stack[AREG].float_int < machine->stack[BREG].float_int;
		break;
	case OP_CODE_LONG_ADD:
		machine->stack[CREG].long_int = machine->stack[AREG].long_int + machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_SUBRACT:
		machine->stack[CREG].long_int = machine->stack[AREG].long_int - machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_MULTIPLY:
		machine->stack[CREG].long_int = machine->stack[AREG].long_int * machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_DIVIDE:
		machine->stack[CREG].long_int = machine->stack[AREG].long_int / machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_MODULO:
		machine->stack[CREG].long_int = machine->stack[AREG].long_int % machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_EXPONENTIATE:
		machine->stack[CREG].long_int = longpow(machine->stack[AREG].long_int, machine->stack[BREG].long_int);
		break;
	case OP_CODE_FLOAT_ADD:
		machine->stack[CREG].float_int = machine->stack[AREG].float_int + machine->stack[BREG].float_int;
		break;
	case OP_CODE_FLOAT_SUBTRACT:
		machine->stack[CREG].float_int = machine->stack[AREG].float_int - machine->stack[BREG].float_int;
		break;
	case OP_CODE_FLOAT_MULTIPLY:
		machine->stack[CREG].float_int = machine->stack[AREG].float_int * machine->stack[BREG].float_int;
		break;
	case OP_CODE_FLOAT_DIVIDE:
		machine->stack[CREG].float_int = machine->stack[AREG].float_int / machine->stack[BREG].float_int;
		break;
	case OP_CODE_FLOAT_MODULO:
		machine->stack[CREG].float_int = fmod(machine->stack[AREG].float_int, machine->stack[BREG].float_int);
		break;
	case OP_CODE_FLOAT_EXPONENTIATE:
		machine->stack[CREG].float_int = pow(machine->stack[AREG].float_int, machine->stack[BREG].float_int);
		break;
	case OP_CODE_LONG_TO_FLOAT:
		machine->stack[AREG].float_int = (double)machine->stack[BREG].long_int;
		break;
	case OP_CODE_LONG_NEGATE:
		machine->stack[AREG].long_int = -machine->stack[BREG].long_int;
		break;
	case OP_CODE_FLOAT_NEGATE:
		machine->stack[AREG].float_int = -machine->stack[BREG].float_int;
		break;
	case OP_CODE_ABORT:
		PANIC(machine, ERROR_ABORT);
	}
	machine->ip++;
	return 1;
}

const int init_machine(machine_t* machine, uint16_t stack_size, uint16_t heap_alloc_limit, uint16_t frame_limit) {
	machine->heap_alloc_limit = heap_alloc_limit;
	machine->frame_limit = frame_limit;

	machine->last_err = ERROR_NONE;
	machine->global_offset = 0;
	machine->position_count = 0;
	machine->heap_frame = 0;
	machine->heap_count = 0;
	machine->heap_reset_count = 0;

	ESCAPE_ON_NULL(machine->stack = malloc(stack_size * sizeof(register_t)));
	ESCAPE_ON_NULL(machine->positions = malloc(machine->frame_limit * sizeof(machine_ins_t*)));
	ESCAPE_ON_NULL(machine->heap_allocs = malloc(machine->heap_alloc_limit * sizeof(heap_alloc_t*)));
	ESCAPE_ON_NULL(machine->heap_frame_bounds = malloc(machine->frame_limit * sizeof(uint16_t)));
	ESCAPE_ON_NULL(machine->heap_reset_bounds = malloc(machine->frame_limit * sizeof(uint16_t)));
	return 1;
}

void free_machine(machine_t* machine) {
	free(machine->stack);
	free(machine->positions);
	free(machine->heap_allocs);
	free(machine->heap_frame_bounds);
	free(machine->heap_reset_bounds);
}

const int machine_execute(machine_t* machine, machine_ins_t* instructions, uint16_t instruction_count) {
	machine_ins_t* last_ins = &instructions[instruction_count - 1];
	machine->ip = &instructions[0];
	while (machine->ip <= last_ins)
		ESCAPE_ON_NULL(machine_execute_instruction(machine, instructions));
	return 1;
}