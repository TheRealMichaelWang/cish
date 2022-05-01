#include <stdlib.h>
#include <math.h>
#include "error.h"
#include "type.h"
#include "machine.h"

static int64_t longpow(int64_t base, int64_t exp) {
	int64_t result = 1;
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

heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, gc_trace_mode_t trace_mode) {
	if (machine->heap_count == machine->alloced_heap_allocs) {
		heap_alloc_t** new_heap_allocs = realloc(machine->heap_allocs, (machine->alloced_heap_allocs += 100) * sizeof(heap_alloc_t*));
		PANIC_ON_FAIL(new_heap_allocs, machine, ERROR_MEMORY);
		machine->heap_allocs = new_heap_allocs;
	}

	heap_alloc_t* heap_alloc;
	if (machine->freed_heap_count) {
		heap_alloc = machine->freed_heap_allocs[--machine->freed_heap_count];
		if(!heap_alloc->reg_with_table)
			machine->heap_allocs[machine->heap_count++] = heap_alloc;
	}
	else {
		heap_alloc = malloc(sizeof(heap_alloc_t));
		PANIC_ON_FAIL(heap_alloc, machine, ERROR_MEMORY);
		machine->heap_allocs[machine->heap_count++] = heap_alloc;
		heap_alloc->reg_with_table = 1;
	}
	heap_alloc->pre_freed = 0;
	heap_alloc->limit = req_size;
	heap_alloc->gc_flag = 0;
	heap_alloc->trace_mode = trace_mode;
	heap_alloc->type_sig = NULL;
	PANIC_ON_FAIL(heap_alloc, machine, ERROR_MEMORY);
	PANIC_ON_FAIL(heap_alloc->registers = malloc(req_size * sizeof(machine_reg_t)), machine, ERROR_MEMORY);
	PANIC_ON_FAIL(heap_alloc->init_stat = calloc(req_size, sizeof(int)), machine, ERROR_MEMORY);
	if (trace_mode == GC_TRACE_MODE_SOME)
		PANIC_ON_FAIL(heap_alloc->trace_stat = malloc(req_size * sizeof(int)), machine, ERROR_MEMORY);
	return heap_alloc;
}

int free_alloc(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (heap_alloc->pre_freed || heap_alloc->gc_flag)
		return 1;
	heap_alloc->pre_freed = 1;

	switch (heap_alloc->trace_mode) {
	case GC_TRACE_MODE_ALL:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i])
				ESCAPE_ON_FAIL(free_alloc(machine, heap_alloc->registers[i].heap_alloc));
		break;
	case GC_TRACE_MODE_SOME:
		for(uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if(heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
				ESCAPE_ON_FAIL(free_alloc(machine, heap_alloc->registers[i].heap_alloc));
		free(heap_alloc->trace_stat);
		break;
	}

	free(heap_alloc->registers);
	free(heap_alloc->init_stat);

	if (machine->freed_heap_count == machine->alloc_freed_heaps) {
		heap_alloc_t** new_freed_heaps = realloc(machine->freed_heap_allocs, (machine->alloc_freed_heaps += 10) * sizeof(heap_alloc_t*));
		PANIC_ON_FAIL(new_freed_heaps, machine, ERROR_MEMORY);
		machine->freed_heap_allocs = new_freed_heaps;
	}
	machine->freed_heap_allocs[machine->freed_heap_count++] = heap_alloc;
	return 1;
}

static void machine_heap_supertrace(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (heap_alloc->gc_flag)
		return;
	heap_alloc->gc_flag = 1;
	switch (heap_alloc->trace_mode) {
	case GC_TRACE_MODE_ALL:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i])
				machine_heap_supertrace(machine, heap_alloc->registers[i].heap_alloc);
		break;
	case GC_TRACE_MODE_SOME:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
				machine_heap_supertrace(machine, heap_alloc->registers[i].heap_alloc);
		break;
	}
}

static void machine_heap_trace(machine_t* machine, heap_alloc_t* heap_alloc, heap_alloc_t** reset_stack, uint16_t* reset_count) {
	if (heap_alloc->gc_flag)
		return;
	
	if(*reset_count == 128) {
		machine_heap_supertrace(machine, heap_alloc);
		return;
	}
	
	heap_alloc->gc_flag = 1;
	reset_stack[(*reset_count)++] = heap_alloc;
	switch (heap_alloc->trace_mode) {
	case GC_TRACE_MODE_ALL:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i])
				machine_heap_trace(machine, heap_alloc->registers[i].heap_alloc, reset_stack, reset_count);
		break;
	case GC_TRACE_MODE_SOME:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if(heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
				machine_heap_trace(machine, heap_alloc->registers[i].heap_alloc, reset_stack, reset_count);
		break;
	}
}

static int type_signature_match(machine_t* machine, machine_type_sig_t match_signature, machine_type_sig_t parent_signature) {
	if (parent_signature.super_signature == TYPE_ANY)
		return 1;

	if (match_signature.super_signature == TYPE_TYPEARG)
		match_signature = machine->defined_signatures[machine->stack[match_signature.sub_type_count + machine->global_offset].long_int];
	if (parent_signature.super_signature == TYPE_TYPEARG)
		parent_signature = machine->defined_signatures[machine->stack[parent_signature.sub_type_count + machine->global_offset].long_int];

	if (match_signature.super_signature != parent_signature.super_signature) {
		uint16_t match_super_sig = match_signature.super_signature;
		while (machine->type_table[match_super_sig]) {
			match_super_sig = machine->type_table[match_super_sig];
			if (match_super_sig == parent_signature.super_signature)
				goto super_sig_check_ok;
		}
		return 0;
	}
super_sig_check_ok:
	if (match_signature.sub_type_count != parent_signature.sub_type_count)
		return 0;
	for (uint_fast8_t i = 0; i < parent_signature.sub_type_count; i++) {
		if (!type_signature_match(machine, match_signature.sub_types[i], parent_signature.sub_types[i]))
			return 0;
	}
	return 1;
}

int init_machine(machine_t* machine, uint16_t stack_size, uint16_t frame_limit, uint16_t type_count) {
	machine->frame_limit = frame_limit;

	machine->last_err = ERROR_NONE;
	machine->global_offset = 0;
	machine->position_count = 0;
	machine->heap_frame = 0;
	machine->heap_count = 0;
	machine->trace_count = 0;
	machine->freed_heap_count = 0;
	machine->defined_sig_count = 0;

	ESCAPE_ON_FAIL(machine->stack = malloc(stack_size * sizeof(machine_reg_t)));
	ESCAPE_ON_FAIL(machine->positions = malloc(machine->frame_limit * sizeof(machine_ins_t*)));
	ESCAPE_ON_FAIL(machine->heap_allocs = malloc((machine->alloced_heap_allocs = 1000) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(machine->heap_traces = malloc((machine->alloced_trace_allocs = 128) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(machine->heap_frame_bounds = malloc(machine->frame_limit * sizeof(uint16_t)));
	ESCAPE_ON_FAIL(machine->trace_frame_bounds = malloc(machine->frame_limit * sizeof(uint16_t)));
	ESCAPE_ON_FAIL(machine->freed_heap_allocs = malloc((machine->alloc_freed_heaps = 128) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(machine->dynamic_library_table = malloc(sizeof(dynamic_library_table_t)));
	ESCAPE_ON_FAIL(machine->type_table = calloc(type_count, sizeof(uint16_t)));
	ESCAPE_ON_FAIL(machine->defined_signatures = malloc((machine->alloced_sig_defs = 16) * sizeof(machine_type_sig_t)));
	ESCAPE_ON_FAIL(init_ffi(&machine->ffi_table));
	ESCAPE_ON_FAIL(dynamic_library_init(machine->dynamic_library_table));
	return 1;
}

static void free_defined_signature(machine_type_sig_t* type_sig) {
	if (type_sig->super_signature >= TYPE_SUPER_PROC && type_sig->sub_type_count) {
		for (uint_fast8_t i = 0; i < type_sig->sub_type_count; i++)
			free_defined_signature(&type_sig->sub_types[i]);
		free(type_sig->sub_types);
	}
}

void free_machine(machine_t* machine) {
	for (uint_fast16_t i = 0; i < machine->freed_heap_count; i++)
		free(machine->freed_heap_allocs[i]);
	for (uint_fast16_t i = 0; i < machine->defined_sig_count; i++)
		free_defined_signature(&machine->defined_signatures[i]);
	free(machine->freed_heap_allocs);
	free_ffi(&machine->ffi_table);
	dynamic_library_free(machine->dynamic_library_table);
	free(machine->dynamic_library_table);
	free(machine->stack);
	free(machine->positions);
	free(machine->heap_allocs);
	free(machine->heap_frame_bounds);
	free(machine->heap_traces);
	free(machine->trace_frame_bounds);
	free(machine->type_table);
	free(machine->defined_signatures);
}

machine_type_sig_t* new_type_sig(machine_t* machine) {
	if (machine->defined_sig_count == machine->alloced_sig_defs) {
		machine_type_sig_t* new_sigs = realloc(machine->defined_signatures, (machine->alloced_sig_defs += 10) * sizeof(machine_type_sig_t));
		PANIC_ON_FAIL(new_sigs, machine, ERROR_MEMORY);
		machine->defined_signatures = new_sigs;
	}
	return &machine->defined_signatures[machine->defined_sig_count++];
}

#define MACHINE_PANIC_COND(COND, ERR) {if(!(COND)) { machine->last_err_ip = ip - instructions; PANIC(machine, ERR); }}
#define MACHINE_ESCAPE_COND(COND) {if(!(COND)) { machine->last_err_ip = ip - instructions; return 0; }}
#define MACHINE_PANIC(ERR) {machine->last_err_ip = ip - instructions; PANIC(machine, ERR); };
int machine_execute(machine_t* machine, machine_ins_t* instructions) {
	machine_ins_t* ip = instructions;
	for (;;) {
		switch (ip->op_code) {
		case MACHINE_OP_CODE_MOVE_LL:
			machine->stack[ip->a + machine->global_offset] = machine->stack[ip->b + machine->global_offset];
			break;
		case MACHINE_OP_CODE_MOVE_LG:
			machine->stack[ip->a + machine->global_offset] = machine->stack[ip->b];
			break;
		case MACHINE_OP_CODE_MOVE_GL:
			machine->stack[ip->a] = machine->stack[ip->b + machine->global_offset];
			break;
		case MACHINE_OP_CODE_MOVE_GG:
			machine->stack[ip->a] = machine->stack[ip->b];
			break;
		case MACHINE_OP_CODE_SET_L:
			machine->stack[ip->a + machine->global_offset].long_int = ip->b;
			break;
		case MACHINE_OP_CODE_JUMP:
			ip = &instructions[ip->a];
			continue;
		case MACHINE_OP_CODE_JUMP_CHECK_L:
			if (!machine->stack[ip->a + machine->global_offset].bool_flag) {
				ip = &instructions[ip->b];
				continue;
			}
			break;
		case MACHINE_OP_CODE_JUMP_CHECK_G:
			if (!machine->stack[ip->a].bool_flag) {
				ip = &instructions[ip->b];
				continue;
			}
			break;
		case MACHINE_OP_CODE_CALL_L: {
			MACHINE_PANIC_COND(machine->position_count != machine->frame_limit, ERROR_STACK_OVERFLOW);
			machine->positions[machine->position_count++] = ip;
			uint16_t prev_a = ip->a + machine->global_offset;
			machine->global_offset += ip->b;
			ip = machine->stack[prev_a].ip;
			continue;
		}
		case MACHINE_OP_CODE_CALL_G:
			MACHINE_PANIC_COND(machine->position_count != machine->frame_limit, ERROR_STACK_OVERFLOW);
			machine->positions[machine->position_count++] = ip;
			machine->global_offset += ip->b;
			ip = machine->stack[ip->a].ip;
			continue;
		case MACHINE_OP_CODE_LABEL_L:
			machine->stack[ip->a + machine->global_offset].ip = &instructions[ip->b];
			break;
		case MACHINE_OP_CODE_LABEL_G:
			machine->stack[ip->a].ip = &instructions[ip->b];
			break;
		case MACHINE_OP_CODE_RETURN:
			ip = machine->positions[--machine->position_count];
			break;
		{
			heap_alloc_t* array_register;
			int64_t index_register;
			machine_reg_t* dest_reg;
		case MACHINE_OP_CODE_LOAD_ALLOC_LLL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b + +machine->global_offset].long_int;
			dest_reg = &machine->stack[ip->c + machine->global_offset];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_LLG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b + +machine->global_offset].long_int;
			dest_reg = &machine->stack[ip->c];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_LGL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			dest_reg = &machine->stack[ip->c + machine->global_offset];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_LGG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			dest_reg = &machine->stack[ip->c];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_GLL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b + +machine->global_offset].long_int;
			dest_reg = &machine->stack[ip->c + machine->global_offset];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_GLG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b + +machine->global_offset].long_int;
			dest_reg = &machine->stack[ip->c];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_GGL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			dest_reg = &machine->stack[ip->c + machine->global_offset];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_GGG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			dest_reg = &machine->stack[ip->c];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b + machine->global_offset];
			goto load_alloc_unbounded;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b];
			goto load_alloc_unbounded;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b + machine->global_offset];
			goto load_alloc_unbounded;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b];
			goto load_alloc_unbounded;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_BOUND_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b + machine->global_offset];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_BOUND_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_BOUND_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b + machine->global_offset];
			goto load_alloc_bounds;
		case MACHINE_OP_CODE_LOAD_ALLOC_I_BOUND_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			dest_reg = &machine->stack[ip->b];
			goto load_alloc_bounds;
		load_alloc_bounds:
			if (index_register < 0 || index_register >= array_register->limit)
				MACHINE_PANIC(ERROR_INDEX_OUT_OF_RANGE);
		load_alloc_unbounded:
			if (!array_register->init_stat[index_register])
				MACHINE_PANIC(ERROR_READ_UNINIT);
			*dest_reg = array_register->registers[index_register];
			break;
		}
		{
			heap_alloc_t* array_register;
			int64_t index_register;
			machine_reg_t* store_reg;
		case MACHINE_OP_CODE_STORE_ALLOC_LLL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = &machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_LLG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = &machine->stack[ip->c];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_LGL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = &machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_LGG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = &machine->stack[ip->c];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GLL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = &machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GLG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = &machine->stack[ip->c];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GGL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = &machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GGG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = &machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b + machine->global_offset];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b + machine->global_offset];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = &machine->stack[ip->b];
			goto store_alloc_bounds;
		store_alloc_bounds:
			if (index_register < 0 || index_register >= array_register->limit)
				MACHINE_PANIC(ERROR_INDEX_OUT_OF_RANGE);
		store_alloc_unbounded:
			array_register->registers[index_register] = *store_reg;
			array_register->init_stat[index_register] = 1;
			break;
		}
		case MACHINE_OP_CODE_DYNAMIC_CONF_LL:
			machine->stack[ip->a + machine->global_offset].heap_alloc->trace_stat[ip->b] = machine->stack[ip->c + machine->global_offset].long_int >= TYPE_SUPER_ARRAY;
			break;
		case MACHINE_OP_CODE_DYNAMIC_CONF_ALL_LL:
			machine->stack[ip->a + machine->global_offset].heap_alloc->trace_mode = machine->stack[ip->b + machine->global_offset].long_int >= TYPE_SUPER_ARRAY;
			break;
		case MACHINE_OP_CODE_CONF_TRACE_L:
			machine->stack[ip->a + machine->global_offset].heap_alloc->trace_stat[ip->b] = ip->c;
			break;
		case MACHINE_OP_CODE_CONF_TRACE_G:
			machine->stack[ip->a].heap_alloc->trace_stat[ip->b] = ip->c;
			break;
		case MACHINE_OP_CODE_STACK_OFFSET:
			machine->global_offset += ip->a;
			break;
		case MACHINE_OP_CODE_STACK_DEOFFSET:
			machine->global_offset -= ip->a;
			break;
		case MACHINE_OP_CODE_ALLOC_LL:
			MACHINE_ESCAPE_COND(machine->stack[ip->a + machine->global_offset].heap_alloc = machine_alloc(machine, machine->stack[ip->b + machine->global_offset].long_int, ip->c));
			break;
		case MACHINE_OP_CODE_ALLOC_LG:
			MACHINE_ESCAPE_COND(machine->stack[ip->a + machine->global_offset].heap_alloc = machine_alloc(machine, machine->stack[ip->b].long_int, ip->c));
			break;
		case MACHINE_OP_CODE_ALLOC_GL:
			MACHINE_ESCAPE_COND(machine->stack[ip->a].heap_alloc = machine_alloc(machine, machine->stack[ip->b + machine->global_offset].long_int, ip->c));
			break;
		case MACHINE_OP_CODE_ALLOC_GG:
			MACHINE_ESCAPE_COND(machine->stack[ip->a].heap_alloc = machine_alloc(machine, machine->stack[ip->b].long_int, ip->c));
			break;
		case MACHINE_OP_CODE_ALLOC_I_L:
			MACHINE_ESCAPE_COND(machine->stack[ip->a + machine->global_offset].heap_alloc = machine_alloc(machine, ip->b, ip->c));
			break;
		case MACHINE_OP_CODE_ALLOC_I_G:
			MACHINE_ESCAPE_COND(machine->stack[ip->a].heap_alloc = machine_alloc(machine, ip->b, ip->c));
			break;
		case MACHINE_OP_CODE_DYNAMIC_FREE_LL:
			if (!machine->stack[ip->b + machine->global_offset].long_int >= TYPE_SUPER_ARRAY)
				break;
		case MACHINE_OP_CODE_FREE_L:
			MACHINE_ESCAPE_COND(free_alloc(machine, machine->stack[ip->a + machine->global_offset].heap_alloc));
			break;
		case MACHINE_OP_CODE_FREE_G:
			MACHINE_ESCAPE_COND(free_alloc(machine, machine->stack[ip->a].heap_alloc));
			break;
		case MACHINE_OP_CODE_GC_NEW_FRAME:
			if (machine->heap_frame == machine->frame_limit)
				MACHINE_PANIC(ERROR_STACK_OVERFLOW);
			machine->heap_frame_bounds[machine->heap_frame] = machine->heap_count;
			machine->trace_frame_bounds[machine->heap_frame] = machine->trace_count;
			machine->heap_frame++;
			break; 
		{
			int super_traced;
			heap_alloc_t* heap_alloc;
		case MACHINE_OP_CODE_DYNAMIC_TRACE_LL:
			if (!machine->stack[ip->b + machine->global_offset].long_int >= TYPE_SUPER_ARRAY)
				break;
			super_traced = 0;
			heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			goto not_super_traced;
		case MACHINE_OP_CODE_GC_TRACE_L:
			heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			goto maybe_super_traced;
		case MACHINE_OP_CODE_GC_TRACE_G:
			heap_alloc = machine->stack[ip->a].heap_alloc;
			goto maybe_super_traced;
		maybe_super_traced:
			super_traced = ip->b;
		not_super_traced:
			if (machine->trace_count == machine->alloced_trace_allocs) {
				heap_alloc_t** new_trace_stack = realloc(machine->heap_traces, (machine->alloced_trace_allocs += 10) * sizeof(heap_alloc_t*));
				MACHINE_PANIC_COND(new_trace_stack, ERROR_MEMORY);
				machine->heap_traces = new_trace_stack;
			}
			(machine->heap_traces[machine->trace_count++] = heap_alloc)->gc_flag = super_traced;
			break;
		}
		case MACHINE_OP_CODE_GC_CLEAN: {
			uint16_t reseted_heap_count = 0;
			static heap_alloc_t* reset_stack[128];
			
			--machine->heap_frame;
			heap_alloc_t** frame_start = &machine->heap_allocs[machine->heap_frame_bounds[machine->heap_frame]];
			heap_alloc_t** frame_end = &machine->heap_allocs[machine->heap_count];
			
			if (machine->heap_frame) {
				for (uint_fast16_t i = machine->trace_frame_bounds[machine->heap_frame]; i < machine->trace_count; i++)
					if (machine->heap_traces[i]->gc_flag) {
						machine->heap_traces[i]->gc_flag = 0;
						machine_heap_supertrace(machine, machine->heap_traces[i]);
					}
					else
						machine_heap_trace(machine, machine->heap_traces[i], reset_stack, &reseted_heap_count);

				for (heap_alloc_t** current_alloc = frame_start; current_alloc != frame_end; current_alloc++) {
					if ((*current_alloc)->gc_flag)
						*frame_start++ = *current_alloc;
					else if ((*current_alloc)->pre_freed)
						(*current_alloc)->reg_with_table = 0;
					else {
						free((*current_alloc)->registers);
						free((*current_alloc)->init_stat);
						if ((*current_alloc)->trace_mode == GC_TRACE_MODE_SOME)
							free((*current_alloc)->trace_stat);
						free((*current_alloc));
					}
				}
				machine->heap_count = frame_start - machine->heap_allocs;
				machine->trace_count = machine->trace_frame_bounds[machine->heap_frame];
				for (uint_fast16_t i = 0; i < reseted_heap_count; i++)
					reset_stack[i]->gc_flag = 0;
			}
			else {
				for (heap_alloc_t** current_alloc = frame_start; current_alloc != frame_end; current_alloc++)
					if (!(*current_alloc)->pre_freed) {
						free((*current_alloc)->registers);
						free((*current_alloc)->init_stat);
						if ((*current_alloc)->trace_mode == GC_TRACE_MODE_SOME)
							free((*current_alloc)->trace_stat);
						free((*current_alloc));
					}
				machine->heap_count = 0;
			}
			break;
		}
		case MACHINE_OP_CODE_AND_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag && machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag && machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag && machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag && machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].bool_flag && machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].bool_flag && machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].bool_flag && machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_AND_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].bool_flag && machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag || machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag || machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag || machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag || machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].bool_flag || machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].bool_flag || machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].bool_flag || machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_OR_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].bool_flag || machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_NOT_LL:
			machine->stack[ip->a + machine->global_offset].bool_flag = !machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_NOT_LG:
			machine->stack[ip->a + machine->global_offset].bool_flag = !machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_NOT_GL:
			machine->stack[ip->a].bool_flag = !machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_NOT_GG:
			machine->stack[ip->a].bool_flag = !machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_LENGTH_LL:
			machine->stack[ip->a + machine->global_offset].long_int = machine->stack[ip->b + machine->global_offset].heap_alloc->limit;
			break;
		case MACHINE_OP_CODE_LENGTH_LG:
			machine->stack[ip->a + machine->global_offset].long_int= machine->stack[ip->b].heap_alloc->limit;
			break;
		case MACHINE_OP_CODE_LENGTH_GL:
			machine->stack[ip->a].long_int= machine->stack[ip->b + machine->global_offset].heap_alloc->limit;
			break;
		case MACHINE_OP_CODE_LENGTH_GG:
			machine->stack[ip->a].long_int= machine->stack[ip->b].heap_alloc->limit;
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].ip == machine->stack[ip->b + machine->global_offset].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].ip == machine->stack[ip->b + machine->global_offset].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].ip == machine->stack[ip->b].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].ip == machine->stack[ip->b].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].ip == machine->stack[ip->b + machine->global_offset].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].ip == machine->stack[ip->b + machine->global_offset].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].ip == machine->stack[ip->b].ip; 
			break;
		case MACHINE_OP_CODE_PTR_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].ip == machine->stack[ip->b].ip; 
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag == machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag == machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag == machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].bool_flag == machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].bool_flag == machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].bool_flag == machine->stack[ip->b + machine->global_offset].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].bool_flag == machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_BOOL_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].bool_flag == machine->stack[ip->b].bool_flag;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].char_int == machine->stack[ip->b + machine->global_offset].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].char_int == machine->stack[ip->b + machine->global_offset].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].char_int == machine->stack[ip->b].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].char_int == machine->stack[ip->b].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].char_int == machine->stack[ip->b + machine->global_offset].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].char_int == machine->stack[ip->b + machine->global_offset].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].char_int == machine->stack[ip->b].char_int;
			break;
		case MACHINE_OP_CODE_CHAR_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].char_int == machine->stack[ip->b].char_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int == machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int == machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int == machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int == machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int == machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int == machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int == machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int == machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int == machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int == machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int == machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int == machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int == machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int == machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int == machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int == machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int >= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int >= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int >= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int >= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int >= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int >= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int >= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int >= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int <= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int <= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int <= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int <= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int <= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int <= machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int <= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int <= machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int > machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int > machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int > machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int > machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int > machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int > machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int > machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MORE_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int > machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int < machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int < machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].long_int < machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].long_int < machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int < machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int < machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].long_int < machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_LESS_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].long_int < machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_LLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int + machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_LLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int + machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_LGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int + machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_LGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int + machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_GLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int + machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_GLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int + machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_GGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int + machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_ADD_GGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int + machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_LLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int - machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_LLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int - machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_LGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int - machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_LGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int - machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_GLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int - machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_GLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int - machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_GGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int - machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_SUBTRACT_GGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int - machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_LLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int * machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_LLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int * machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_LGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int * machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_LGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int * machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_GLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int * machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_GLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int * machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_GGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int * machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MULTIPLY_GGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int * machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_DIVIDE_LLL: {
			uint64_t d = machine->stack[ip->b + machine->global_offset].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_LLG: {
			uint64_t d = machine->stack[ip->b + machine->global_offset].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_LGL: {
			uint64_t d = machine->stack[ip->b].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_LGG: {
			uint64_t d = machine->stack[ip->b].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_GLL: {
			uint64_t d = machine->stack[ip->b + machine->global_offset].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_GLG: {
			uint64_t d = machine->stack[ip->b + machine->global_offset].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_GGL: {
			uint64_t d = machine->stack[ip->b].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_DIVIDE_GGG: {
			uint64_t d = machine->stack[ip->b].long_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int / d;
			break;
		}
		case MACHINE_OP_CODE_LONG_MODULO_LLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int % machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_LLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int % machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_LGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a + machine->global_offset].long_int % machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_LGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a + machine->global_offset].long_int % machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_GLL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int % machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_GLG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int % machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_GGL:
			machine->stack[ip->c + machine->global_offset].long_int = machine->stack[ip->a].long_int % machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_MODULO_GGG:
			machine->stack[ip->c].long_int = machine->stack[ip->a].long_int % machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_LLL:
			machine->stack[ip->c + machine->global_offset].long_int = longpow(machine->stack[ip->a + machine->global_offset].long_int, machine->stack[ip->b + machine->global_offset].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_LLG:
			machine->stack[ip->c].long_int = longpow(machine->stack[ip->a + machine->global_offset].long_int, machine->stack[ip->b + machine->global_offset].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_LGL:
			machine->stack[ip->c + machine->global_offset].long_int = longpow(machine->stack[ip->a + machine->global_offset].long_int, machine->stack[ip->b].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_LGG:
			machine->stack[ip->c].long_int = longpow(machine->stack[ip->a + machine->global_offset].long_int, machine->stack[ip->b].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_GLL:
			machine->stack[ip->c + machine->global_offset].long_int = longpow(machine->stack[ip->a].long_int, machine->stack[ip->b + machine->global_offset].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_GLG:
			machine->stack[ip->c].long_int = longpow(machine->stack[ip->a].long_int, machine->stack[ip->b + machine->global_offset].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_GGL:
			machine->stack[ip->c + machine->global_offset].long_int = longpow(machine->stack[ip->a].long_int, machine->stack[ip->b].long_int);
			break;
		case MACHINE_OP_CODE_LONG_EXPONENTIATE_GGG:
			machine->stack[ip->c].long_int = longpow(machine->stack[ip->a].long_int, machine->stack[ip->b].long_int);
			break; 
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int >= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int >= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int >= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int >= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int >= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int >= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int >= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int >= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int <= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int <= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int <= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int <= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int <= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int <= machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int <= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_EQUAL_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int <= machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int > machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int > machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int > machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int > machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int > machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int > machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int > machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MORE_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int > machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_LLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int < machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_LLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int < machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_LGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a + machine->global_offset].float_int < machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_LGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a + machine->global_offset].float_int < machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_GLL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int < machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_GLG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int < machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_GGL:
			machine->stack[ip->c + machine->global_offset].bool_flag = machine->stack[ip->a].float_int < machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_LESS_GGG:
			machine->stack[ip->c].bool_flag = machine->stack[ip->a].float_int < machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_LLL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int + machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_LLG:
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int + machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_LGL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int + machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_LGG:
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int + machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_GLL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int + machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_GLG:
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int + machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_GGL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int + machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_ADD_GGG:
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int + machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_LLL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int - machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_LLG:
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int - machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_LGL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int - machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_LGG:
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int - machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_GLL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int - machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_GLG:
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int - machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_GGL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int - machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_SUBTRACT_GGG:
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int - machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_LLL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int * machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_LLG:
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int * machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_LGL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int * machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_LGG:
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int * machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_GLL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int * machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_GLG:
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int * machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_GGL:
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int * machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_MULTIPLY_GGG:
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int * machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LLL: {
			double d = machine->stack[ip->b + machine->global_offset].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LLG: {
			double d = machine->stack[ip->b + machine->global_offset].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LGL: {
			double d = machine->stack[ip->b].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LGG: {
			double d = machine->stack[ip->b].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GLL: {
			double d = machine->stack[ip->b + machine->global_offset].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GLG: {
			double d = machine->stack[ip->b + machine->global_offset].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GGL: {
			double d = machine->stack[ip->b].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GGG: {
			double d = machine->stack[ip->b].float_int;
			MACHINE_PANIC_COND(d, ERROR_DIVIDE_BY_ZERO);
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int / d;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_MODULO_LLL:
			machine->stack[ip->c + machine->global_offset].float_int = fmod(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_LLG:
			machine->stack[ip->c].float_int = fmod(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_LGL:
			machine->stack[ip->c + machine->global_offset].float_int = fmod(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_LGG:
			machine->stack[ip->c].float_int = fmod(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_GLL:
			machine->stack[ip->c + machine->global_offset].float_int = fmod(machine->stack[ip->a].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_GLG:
			machine->stack[ip->c].float_int = fmod(machine->stack[ip->a].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_GGL:
			machine->stack[ip->c + machine->global_offset].float_int = fmod(machine->stack[ip->a].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_MODULO_GGG:
			machine->stack[ip->c].float_int = fmod(machine->stack[ip->a].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_LLL:
			machine->stack[ip->c + machine->global_offset].float_int = pow(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_LLG:
			machine->stack[ip->c].float_int = pow(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_LGL:
			machine->stack[ip->c + machine->global_offset].float_int = pow(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_LGG:
			machine->stack[ip->c].float_int = pow(machine->stack[ip->a + machine->global_offset].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_GLL:
			machine->stack[ip->c + machine->global_offset].float_int = pow(machine->stack[ip->a].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_GLG:
			machine->stack[ip->c].float_int = pow(machine->stack[ip->a].float_int, machine->stack[ip->b + machine->global_offset].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_GGL:
			machine->stack[ip->c + machine->global_offset].float_int = pow(machine->stack[ip->a].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_FLOAT_EXPONENTIATE_GGG:
			machine->stack[ip->c].float_int = pow(machine->stack[ip->a].float_int, machine->stack[ip->b].float_int);
			break;
		case MACHINE_OP_CODE_LONG_NEGATE_LL:
			machine->stack[ip->a + machine->global_offset].long_int = -machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_NEGATE_LG:
			machine->stack[ip->a + machine->global_offset].long_int = -machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_LONG_NEGATE_GL:
			machine->stack[ip->a].long_int = -machine->stack[ip->b + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_NEGATE_GG:
			machine->stack[ip->a].long_int = -machine->stack[ip->b].long_int;
			break;
		case MACHINE_OP_CODE_FLOAT_NEGATE_LL:
			machine->stack[ip->a + machine->global_offset].float_int = -machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_NEGATE_LG:
			machine->stack[ip->a + machine->global_offset].float_int = -machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_NEGATE_GL:
			machine->stack[ip->a].float_int = -machine->stack[ip->b + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_NEGATE_GG:
			machine->stack[ip->a].float_int = -machine->stack[ip->b].float_int;
			break;
		case MACHINE_OP_CODE_ABORT:
			if (ip->a == ERROR_NONE)
				return 1;
			else
				MACHINE_PANIC(ip->a);
		{
			machine_reg_t* a;
			machine_reg_t* b;
			machine_reg_t* c;
		case MACHINE_OP_CODE_FOREIGN_LLL:
			a = &machine->stack[ip->a + machine->global_offset];
			b = &machine->stack[ip->b + machine->global_offset];
			c = &machine->stack[ip->c + machine->global_offset];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_LLG:
			a = &machine->stack[ip->a + machine->global_offset];
			b = &machine->stack[ip->b + machine->global_offset];
			c = &machine->stack[ip->c];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_LGL:
			a = &machine->stack[ip->a + machine->global_offset];
			b = &machine->stack[ip->b];
			c = &machine->stack[ip->c + machine->global_offset];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_LGG:
			a = &machine->stack[ip->a + machine->global_offset];
			b = &machine->stack[ip->b];
			c = &machine->stack[ip->c];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_GLL:
			a = &machine->stack[ip->a];
			b = &machine->stack[ip->b + machine->global_offset];
			c = &machine->stack[ip->c + machine->global_offset];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_GLG:
			a = &machine->stack[ip->a];
			b = &machine->stack[ip->b + machine->global_offset];
			c = &machine->stack[ip->c];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_GGL:
			a = &machine->stack[ip->a];
			b = &machine->stack[ip->b];
			c = &machine->stack[ip->c + machine->global_offset];
			goto invoke_foreign;
		case MACHINE_OP_CODE_FOREIGN_GGG:
			a = &machine->stack[ip->a];
			b = &machine->stack[ip->b];
			c = &machine->stack[ip->c];
			goto invoke_foreign;
		invoke_foreign:
			if (!ffi_invoke(&machine->ffi_table, machine, a, b, c)) {
				if (machine->last_err == ERROR_NONE) {
					MACHINE_PANIC(ERROR_FOREIGN)
				}
				else
					MACHINE_PANIC(machine->last_err);
			}
			break;
		}
		//runtime typing functionality opcode implementations
		case MACHINE_OP_CODE_TYPE_RELATE:
			machine->type_table[ip->a] = ip->b;
			break;
		case MACHINE_OP_CODE_CONFIG_TYPESIG_L:
			machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig = &machine->defined_signatures[ip->b];
			break;
		case MACHINE_OP_CODE_CONFIG_TYPESIG_G:
			machine->stack[ip->a].heap_alloc->type_sig = &machine->defined_signatures[ip->b];
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECHECK_LL:
			machine->stack[ip->b + machine->global_offset].bool_flag = type_signature_match(machine, *machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig, machine->defined_signatures[ip->c]);
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECHECK_LG:
			machine->stack[ip->b].bool_flag = type_signature_match(machine, *machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig, machine->defined_signatures[ip->c]);
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECHECK_GL:
			machine->stack[ip->b + machine->global_offset].bool_flag = type_signature_match(machine, *machine->stack[ip->a].heap_alloc->type_sig, machine->defined_signatures[ip->c]);
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECHECK_GG:
			machine->stack[ip->b].bool_flag = type_signature_match(machine, *machine->stack[ip->a].heap_alloc->type_sig, machine->defined_signatures[ip->c]);
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECAST_LL:
			MACHINE_PANIC_COND(type_signature_match(machine, *machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig, machine->defined_signatures[ip->c]), ERROR_UNEXPECTED_TYPE);
			machine->stack[ip->b + machine->global_offset].heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECAST_LG:
			MACHINE_PANIC_COND(type_signature_match(machine, *machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig, machine->defined_signatures[ip->c]), ERROR_UNEXPECTED_TYPE);
			machine->stack[ip->b].heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECAST_GL:
			MACHINE_PANIC_COND(type_signature_match(machine, *machine->stack[ip->a].heap_alloc->type_sig, machine->defined_signatures[ip->c]), ERROR_UNEXPECTED_TYPE);
			machine->stack[ip->b + machine->global_offset].heap_alloc = machine->stack[ip->a].heap_alloc;
			break;
		case MACHINE_OP_CODE_RUNTIME_TYPECAST_GG:
			MACHINE_PANIC_COND(type_signature_match(machine, *machine->stack[ip->a].heap_alloc->type_sig, machine->defined_signatures[ip->c]), ERROR_UNEXPECTED_TYPE);
			machine->stack[ip->b].heap_alloc = machine->stack[ip->a].heap_alloc;
			break;

		case MACHINE_OP_CODE_DYNAMIC_TYPECHECK_DD_L:
			machine->stack[ip->a + machine->global_offset].bool_flag = type_signature_match(machine, 

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ? 
			*machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int], 
				
			machine->defined_signatures[machine->stack[ip->c + machine->global_offset].long_int]);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECHECK_DD_G:
			machine->stack[ip->a].bool_flag = type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[machine->stack[ip->c + machine->global_offset].long_int]);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECHECK_DR_L:
			machine->stack[ip->a + machine->global_offset].bool_flag = type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[ip->c]);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECHECK_DR_G:
			machine->stack[ip->a].bool_flag = type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[ip->c]);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECHECK_RD_L:
			machine->stack[ip->a + machine->global_offset].bool_flag = type_signature_match(machine, *machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig, machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int]);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECHECK_RD_G:
			machine->stack[ip->a].bool_flag = type_signature_match(machine, *machine->stack[ip->a].heap_alloc->type_sig, machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int]);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECAST_DD_L:
			MACHINE_PANIC_COND(type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[machine->stack[ip->c + machine->global_offset].long_int]), ERROR_UNEXPECTED_TYPE);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECAST_DD_G:
			MACHINE_PANIC_COND(type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[machine->stack[ip->c + machine->global_offset].long_int]), ERROR_UNEXPECTED_TYPE);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECAST_DR_L:
			MACHINE_PANIC_COND(type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[ip->c]), ERROR_UNEXPECTED_TYPE);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECAST_DR_G:
			MACHINE_PANIC_COND(type_signature_match(machine,

			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY ?
			*machine->stack[ip->a].heap_alloc->type_sig :
			machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int],

			machine->defined_signatures[ip->c]), ERROR_UNEXPECTED_TYPE);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECAST_RD_L:
			MACHINE_PANIC_COND(type_signature_match(machine, *machine->stack[ip->a + machine->global_offset].heap_alloc->type_sig, machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int]), ERROR_UNEXPECTED_TYPE);
			break;
		case MACHINE_OP_CODE_DYNAMIC_TYPECAST_RD_G:
			MACHINE_PANIC_COND(type_signature_match(machine, *machine->stack[ip->a].heap_alloc->type_sig, machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int]), ERROR_UNEXPECTED_TYPE);
			break;
		}

		ip++;
	}
	return 1;
}
#undef MACHINE_PANIC_COND
#undef MACHINE_PANIC
#undef MACHINE_ESCAPE_COND