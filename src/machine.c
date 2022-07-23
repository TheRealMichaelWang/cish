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
#define CHECK_HEAP_COUNT if(machine->heap_count == UINT16_MAX) \
							PANIC(machine, ERROR_MEMORY); \
						if (machine->heap_count == machine->alloced_heap_allocs) { \
							heap_alloc_t** new_heap_allocs = realloc(machine->heap_allocs, (machine->alloced_heap_allocs += 100) * sizeof(heap_alloc_t*)); \
							PANIC_ON_FAIL(new_heap_allocs, machine, ERROR_MEMORY); \
							machine->heap_allocs = new_heap_allocs; \
						}

	heap_alloc_t* heap_alloc;
	if (machine->freed_heap_count) {
		heap_alloc = machine->freed_heap_allocs[--machine->freed_heap_count];
		if (!heap_alloc->reg_with_table) {
			CHECK_HEAP_COUNT;
			machine->heap_allocs[machine->heap_count++] = heap_alloc;
			heap_alloc->reg_with_table = 1;
		}
	}
	else {
		heap_alloc = malloc(sizeof(heap_alloc_t));
		PANIC_ON_FAIL(heap_alloc, machine, ERROR_MEMORY);
		CHECK_HEAP_COUNT;
		machine->heap_allocs[machine->heap_count++] = heap_alloc;
		heap_alloc->reg_with_table = 1;
	}

	heap_alloc->pre_freed = 0;
	heap_alloc->limit = req_size;
	heap_alloc->gc_flag = 0;
	heap_alloc->trace_mode = trace_mode;

	PANIC_ON_FAIL(heap_alloc, machine, ERROR_MEMORY);
	
	if (req_size) {
		PANIC_ON_FAIL(heap_alloc->registers = malloc(req_size * sizeof(machine_reg_t)), machine, ERROR_MEMORY);
		PANIC_ON_FAIL(heap_alloc->init_stat = calloc(req_size, sizeof(int)), machine, ERROR_MEMORY);
		if (trace_mode == GC_TRACE_MODE_SOME)
			PANIC_ON_FAIL(heap_alloc->trace_stat = malloc(req_size * sizeof(int)), machine, ERROR_MEMORY);
	}
	return heap_alloc;
#undef CHECK_HEAP_COUNT
}

static void free_type_signature(machine_type_sig_t* type_sig) {
	if (type_sig->super_signature != TYPE_TYPEARG && type_sig->sub_type_count) {
		for (uint_fast8_t i = 0; i < type_sig->sub_type_count; i++)
			free_type_signature(&type_sig->sub_types[i]);
		free(type_sig->sub_types);
	}
}

static void free_heap_alloc(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (heap_alloc->limit) {
		free(heap_alloc->registers);
		free(heap_alloc->init_stat);
		if (heap_alloc->trace_mode == GC_TRACE_MODE_SOME)
			free(heap_alloc->trace_stat);
	}
	if (!(heap_alloc->type_sig >= machine->defined_signatures && heap_alloc->type_sig < (machine->defined_signatures + machine->defined_sig_count))) {
		free_type_signature(heap_alloc->type_sig);
		free(heap_alloc->type_sig);
	}
}

static int recycle_heap_alloc(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (machine->freed_heap_count == machine->alloc_freed_heaps) {
		heap_alloc_t** new_freed_heaps = realloc(machine->freed_heap_allocs, (machine->alloc_freed_heaps += 10) * sizeof(heap_alloc_t*));
		PANIC_ON_FAIL(new_freed_heaps, machine, ERROR_MEMORY);
		machine->freed_heap_allocs = new_freed_heaps;
	}
	machine->freed_heap_allocs[machine->freed_heap_count++] = heap_alloc;
	return 1;
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
		if (heap_alloc->limit) {
			for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
				if (heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
					ESCAPE_ON_FAIL(free_alloc(machine, heap_alloc->registers[i].heap_alloc));
		}
		break;
	}
	free_heap_alloc(machine, heap_alloc);
	return recycle_heap_alloc(machine, heap_alloc);
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

static void machine_heap_detrace(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (!heap_alloc->gc_flag)
		return;
	heap_alloc->gc_flag = 0;
	switch (heap_alloc->trace_mode) {
	case GC_TRACE_MODE_ALL:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i])
				machine_heap_detrace(machine, heap_alloc->registers[i].heap_alloc);
		break;
	case GC_TRACE_MODE_SOME:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
				machine_heap_detrace(machine, heap_alloc->registers[i].heap_alloc);
		break;
	}
}

static int machine_heap_trace(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (heap_alloc->gc_flag)
		return 1;

	if (machine->reset_count == machine->alloced_reset) {
		heap_alloc_t** new_reset_stack = realloc(machine->reset_stack, (machine->alloced_reset += 32) * sizeof(heap_alloc_t*));
		PANIC_ON_FAIL(new_reset_stack, machine, ERROR_MEMORY);
		machine->reset_stack = new_reset_stack;
	}

	heap_alloc->gc_flag = 1;
	machine->reset_stack[machine->reset_count++] = heap_alloc;

	switch (heap_alloc->trace_mode) {
	case GC_TRACE_MODE_ALL:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i])
				ESCAPE_ON_FAIL(machine_heap_trace(machine, heap_alloc->registers[i].heap_alloc));
		break;
	case GC_TRACE_MODE_SOME:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
				ESCAPE_ON_FAIL(machine_heap_trace(machine, heap_alloc->registers[i].heap_alloc));
		break;
	}
	return 1;
}

static int machine_gc_clean(machine_t* machine) {
	machine->reset_count = 0;

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
				ESCAPE_ON_FAIL(machine_heap_trace(machine, machine->heap_traces[i]));

		for (heap_alloc_t** current_alloc = frame_start; current_alloc != frame_end; current_alloc++) {
			if ((*current_alloc)->gc_flag)
				*frame_start++ = *current_alloc;
			else if ((*current_alloc)->pre_freed)
				(*current_alloc)->reg_with_table = 0;
			else {
				free_heap_alloc(machine, *current_alloc);
				(*current_alloc)->reg_with_table = 0;
				ESCAPE_ON_FAIL(recycle_heap_alloc(machine, *current_alloc));
			}
		}
		machine->heap_count = frame_start - machine->heap_allocs;
		machine->trace_count = machine->trace_frame_bounds[machine->heap_frame];

		for (uint_fast16_t i = 0; i < machine->reset_count; i++)
			machine->reset_stack[i]->gc_flag = 0;
	}
	else {
		for (heap_alloc_t** current_alloc = frame_start; current_alloc != frame_end; current_alloc++) {
			if (!(*current_alloc)->pre_freed) {
				free_heap_alloc(machine, *current_alloc);
				free(*current_alloc);
			}
		}
		machine->heap_count = 0;
	}
	return 1;
}

//makes a copy of a type signature, given a prototype defined signature which may contain context dependent type parameters that may escape
static int atomize_heap_type_sig(machine_t* machine, machine_type_sig_t prototype, machine_type_sig_t* output, int atom_typeargs) {
	if (prototype.super_signature == TYPE_TYPEARG && atom_typeargs)
		return atomize_heap_type_sig(machine, machine->defined_signatures[machine->stack[prototype.sub_type_count + machine->global_offset].long_int], output, 1);
	else {
		output->super_signature = prototype.super_signature;
		if ((output->sub_type_count = prototype.sub_type_count) && prototype.super_signature != TYPE_TYPEARG) {
			PANIC_ON_FAIL(output->sub_types = malloc(prototype.sub_type_count * sizeof(machine_type_sig_t)), machine, ERROR_MEMORY);
			for (uint_fast8_t i = 0; i < output->sub_type_count; i++)
				ESCAPE_ON_FAIL(atomize_heap_type_sig(machine, prototype.sub_types[i], &output->sub_types[i], atom_typeargs));
		}
	}
	return 1;
}

static int get_super_type(machine_t* machine, machine_type_sig_t* child_typeargs, machine_type_sig_t* output) {
	if (output->super_signature == TYPE_TYPEARG)
		ESCAPE_ON_FAIL(atomize_heap_type_sig(machine, child_typeargs[output->sub_type_count], output, 1))
	else {
		for (uint_fast8_t i = 0; i < output->sub_type_count; i++)
			ESCAPE_ON_FAIL(get_super_type(machine, child_typeargs, &output->sub_types[i]));
	}
	return 1;
}

static int is_super_type(machine_t* machine, uint16_t child_sig, uint16_t super_sig) {
	if (super_sig < TYPE_SUPER_RECORD || child_sig < TYPE_SUPER_RECORD)
		return 0;
	while (machine->type_table[child_sig - TYPE_SUPER_RECORD])
	{
		child_sig = machine->defined_signatures[machine->type_table[child_sig - TYPE_SUPER_RECORD] - 1].super_signature;
		if (child_sig == super_sig)
			return 1;
	}
	return 0;
}

static int downcast_type_signature(machine_t* machine, machine_type_sig_t* sig, uint16_t req_record) {
	if (sig->super_signature < TYPE_SUPER_RECORD)
		return 0;

	while (sig->super_signature != req_record)
	{
		machine_type_sig_t super_type;
		ESCAPE_ON_FAIL(atomize_heap_type_sig(machine, machine->defined_signatures[machine->type_table[sig->super_signature - TYPE_SUPER_RECORD] - 1], &super_type, 0));
		ESCAPE_ON_FAIL(get_super_type(machine, sig->sub_types, &super_type));
		free_type_signature(sig);
		*sig = super_type;
	}
	return 1;
}

static int type_signature_match(machine_t* machine, machine_type_sig_t match_signature, machine_type_sig_t parent_signature) {
	if (parent_signature.super_signature == TYPE_ANY)
		return 1;

	if (match_signature.super_signature == TYPE_TYPEARG)
		match_signature = machine->defined_signatures[machine->stack[match_signature.sub_type_count + machine->global_offset].long_int];
	if (parent_signature.super_signature == TYPE_TYPEARG)
		parent_signature = machine->defined_signatures[machine->stack[parent_signature.sub_type_count + machine->global_offset].long_int];

	if (match_signature.super_signature != parent_signature.super_signature) {
		if (is_super_type(machine, match_signature.super_signature, parent_signature.super_signature)) {
			/*machine_type_sig_t super_type;
			ESCAPE_ON_FAIL(atomize_heap_type_sig(machine, machine->defined_signatures[machine->type_table[match_signature.super_signature - TYPE_SUPER_RECORD] - 1], &super_type, 0));
			ESCAPE_ON_FAIL(get_super_type(machine, match_signature.sub_types, &super_type));
			int res = type_signature_match(machine, super_type, parent_signature);
			free_type_signature(&super_type);*/
			ESCAPE_ON_FAIL(atomize_heap_type_sig(machine, match_signature, &match_signature, 0));
			ESCAPE_ON_FAIL(downcast_type_signature(machine, &match_signature, parent_signature.super_signature));
			int res = type_signature_match(machine, match_signature, parent_signature);
			free_type_signature(&match_signature);
			return res;
		}
		return 0;
	}
	ESCAPE_ON_FAIL(match_signature.sub_type_count == parent_signature.sub_type_count);
	for (uint_fast8_t i = 0; i < parent_signature.sub_type_count; i++)
		ESCAPE_ON_FAIL(type_signature_match(machine, match_signature.sub_types[i], parent_signature.sub_types[i]));
	return 1;
}

int init_machine(machine_t* machine, uint16_t stack_size, uint16_t frame_limit, uint16_t type_count) {
	machine->frame_limit = frame_limit;
	machine->stack_size = stack_size;

	machine->global_offset = 0;
	machine->position_count = 0;
	machine->heap_frame = 0;
	machine->heap_count = 0;
	machine->trace_count = 0;
	machine->freed_heap_count = 0;
	machine->defined_sig_count = 0;
	machine->reset_count = 0;

	ESCAPE_ON_FAIL(machine->stack = malloc(stack_size * sizeof(machine_reg_t)));
	ESCAPE_ON_FAIL(machine->positions = malloc(machine->frame_limit * sizeof(machine_ins_t*)));
	ESCAPE_ON_FAIL(machine->heap_allocs = malloc((machine->alloced_heap_allocs = frame_limit) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(machine->heap_traces = malloc((machine->alloced_trace_allocs = 128) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(machine->heap_frame_bounds = malloc(machine->frame_limit * sizeof(uint16_t)));
	ESCAPE_ON_FAIL(machine->trace_frame_bounds = malloc(machine->frame_limit * sizeof(uint16_t)));
	ESCAPE_ON_FAIL(machine->freed_heap_allocs = malloc((machine->alloc_freed_heaps = 128) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(machine->dynamic_library_table = malloc(sizeof(dynamic_library_table_t)));
	ESCAPE_ON_FAIL(machine->type_table = calloc(type_count, sizeof(uint16_t)));
	ESCAPE_ON_FAIL(machine->defined_signatures = malloc((machine->alloced_sig_defs = 16) * sizeof(machine_type_sig_t)));
	ESCAPE_ON_FAIL(machine->reset_stack = malloc((machine->alloced_reset = 128) * sizeof(heap_alloc_t*)));
	ESCAPE_ON_FAIL(init_ffi(&machine->ffi_table));
	ESCAPE_ON_FAIL(dynamic_library_init(machine->dynamic_library_table));
	return 1;
}

void free_machine(machine_t* machine) {
	for (uint_fast16_t i = 0; i < machine->freed_heap_count; i++)
		free(machine->freed_heap_allocs[i]);
	for (uint_fast16_t i = 0; i < machine->defined_sig_count; i++)
		free_type_signature(&machine->defined_signatures[i]);
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
	free(machine->reset_stack);
}

static machine_type_sig_t* new_type_sig(machine_t* machine, int no_realloc) {
	if (machine->defined_sig_count == machine->alloced_sig_defs) {
		if (no_realloc)
			return NULL;
		machine_type_sig_t* new_sigs = realloc(machine->defined_signatures, (machine->alloced_sig_defs += 10) * sizeof(machine_type_sig_t));
		PANIC_ON_FAIL(new_sigs, machine, ERROR_MEMORY);
		machine->defined_signatures = new_sigs;
	}
	return &machine->defined_signatures[machine->defined_sig_count++];
}

static int type_sigs_eq(machine_type_sig_t a, machine_type_sig_t b) {
	if (a.super_signature != b.super_signature)
		return 0;
	ESCAPE_ON_FAIL(a.sub_type_count == b.sub_type_count);

	if (a.super_signature != TYPE_TYPEARG && a.sub_type_count) {
		for (uint_fast8_t i = 0; i < a.sub_type_count; i++)
			if (!type_sigs_eq(a.sub_types[i], b.sub_types[i]))
				return 0;
	}
	return 1;
}

machine_type_sig_t* machine_get_typesig(machine_t* machine, machine_type_sig_t* t, int optimize_common) {
	if (optimize_common) {
		for (uint_fast16_t i = 0; i < machine->defined_sig_count; i++)
			if (type_sigs_eq(machine->defined_signatures[i], *t)) {
				//free_type_signature(t);
				return &machine->defined_signatures[i];
			}
	}

	machine_type_sig_t* new_sig = new_type_sig(machine, 0);
	PANIC_ON_FAIL(new_sig, machine, ERROR_MEMORY);
	*new_sig = *t;
	return new_sig;
}

#define MACHINE_PANIC_COND(COND, ERR) {if(!(COND)) { machine->last_err_ip = ip - instructions; PANIC(machine, ERR); }}
#define MACHINE_ESCAPE_COND(COND) {if(!(COND)) { machine->last_err_ip = ip - instructions; return 0; }}
#define MACHINE_PANIC(ERR) {machine->last_err_ip = ip - instructions; PANIC(machine, ERR); }
int machine_execute(machine_t* machine, machine_ins_t* instructions, machine_ins_t* continue_instructions, int first_run) {
	machine_ins_t* ip = continue_instructions;
	machine->last_err = ERROR_NONE;
	
	if(first_run) {
		if (machine->alloced_sig_defs < machine->defined_sig_count + (machine->frame_limit / 4)) {
			machine_type_sig_t* new_sigs = realloc(machine->defined_signatures,sizeof(machine_type_sig_t) * (machine->alloced_sig_defs = machine->defined_sig_count + (machine->frame_limit / 4)));
			MACHINE_PANIC_COND(new_sigs, ERROR_MEMORY);
			machine->defined_signatures = new_sigs;
		}
	}

#ifdef CISH_PAUSABLE
	machine->halt_flag = 0;
	machine->halted = 0;
#endif // CISH_PAUSABLE

	for (;;) {
#ifdef CISH_PAUSABLE
		if (machine->halt_flag) {
			machine->last_err_ip = ip;
			machine->halted = 1;
			return 1;
		}
#endif // CISH_PAUSABLE
		switch (ip->op_code) {
		case MACHINE_OP_CODE_SET_EXTRA_ARGS:
			machine->extra_a = ip->a;
			machine->extra_b = ip->b;
			machine->extra_c = ip->c;
			break;
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
			if (ip->c) {
				machine->stack[ip->a + machine->global_offset].long_int = machine->defined_sig_count;
				machine_type_sig_t* type_sig = new_type_sig(machine, 1);
				MACHINE_PANIC_COND(type_sig, ERROR_STACK_OVERFLOW);
				MACHINE_ESCAPE_COND(atomize_heap_type_sig(machine, machine->defined_signatures[ip->b], type_sig, 1));
			}
			else
				machine->stack[ip->a + machine->global_offset].long_int = ip->b;
			break;
		case MACHINE_OP_CODE_POP_ATOM_TYPESIGS: {
			if (ip->a > machine->defined_sig_count)
				MACHINE_PANIC(ERROR_STACK_OVERFLOW);
			machine_type_sig_t* end = &machine->defined_signatures[machine->defined_sig_count - ip->a];
			for (machine_type_sig_t* begin = &machine->defined_signatures[machine->defined_sig_count - 1]; begin >= end; --begin)
				free_type_signature(begin);
			machine->defined_sig_count -= ip->a;
			break;
		}
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
		case MACHINE_OP_CODE_STACK_VALIDATE:
			if (machine->global_offset + ip->a >= machine->stack_size)
				MACHINE_PANIC(ERROR_STACK_OVERFLOW);
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
			machine_reg_t store_reg;
		case MACHINE_OP_CODE_STORE_ALLOC_LLL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_LLG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = machine->stack[ip->c];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_LGL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_LGG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = machine->stack[ip->c];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GLL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GLG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b + machine->global_offset].long_int;
			store_reg = machine->stack[ip->c];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GGL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_GGG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = machine->stack[ip->b].long_int;
			store_reg = machine->stack[ip->c + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b + machine->global_offset];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b + machine->global_offset];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b];
			goto store_alloc_unbounded;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b + machine->global_offset];
			goto store_alloc_bounds;
		case MACHINE_OP_CODE_STORE_ALLOC_I_BOUND_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			index_register = ip->c;
			store_reg = machine->stack[ip->b];
			goto store_alloc_bounds;
		store_alloc_bounds:
			if (index_register < 0 || index_register >= array_register->limit)
				MACHINE_PANIC(ERROR_INDEX_OUT_OF_RANGE);
		store_alloc_unbounded:
			array_register->registers[index_register] = store_reg;
			array_register->init_stat[index_register] = 1;
			break;
		}
		case MACHINE_OP_CODE_DYNAMIC_CONF_LL:
			machine->stack[ip->a + machine->global_offset].heap_alloc->trace_stat[ip->b] = machine->defined_signatures[machine->stack[ip->c + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY;
			break;
		case MACHINE_OP_CODE_DYNAMIC_CONF_ALL_LL:
			machine->stack[ip->a + machine->global_offset].heap_alloc->trace_mode = machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY;
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
			if (!(machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY))
				break;
		case MACHINE_OP_CODE_FREE_L: {
			MACHINE_ESCAPE_COND(free_alloc(machine, machine->stack[ip->a + machine->global_offset].heap_alloc));
			break; 
		}
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
			if (!(machine->defined_signatures[machine->stack[ip->b + machine->global_offset].long_int].super_signature >= TYPE_SUPER_ARRAY))
				break;
			super_traced = 0;
			heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			goto do_trace;
		case MACHINE_OP_CODE_GC_TRACE_L:
			heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			super_traced = ip->b;
			goto do_trace;
		case MACHINE_OP_CODE_GC_TRACE_G:
			heap_alloc = machine->stack[ip->a].heap_alloc;
			super_traced = ip->b;
		do_trace:
			if (machine->trace_count == machine->alloced_trace_allocs) {
				heap_alloc_t** new_trace_stack = realloc(machine->heap_traces, (machine->alloced_trace_allocs += 10) * sizeof(heap_alloc_t*));
				MACHINE_PANIC_COND(new_trace_stack, ERROR_MEMORY);
				machine->heap_traces = new_trace_stack;
			}
			if (heap_alloc->gc_flag)
				machine_heap_detrace(machine, heap_alloc);
			(machine->heap_traces[machine->trace_count++] = heap_alloc)->gc_flag = super_traced;
			break;
		}
		case MACHINE_OP_CODE_GC_CLEAN:
			machine_gc_clean(machine);
			break;
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
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int / machine->stack[ip->b + machine->global_offset].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LLG: {
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int / machine->stack[ip->b + machine->global_offset].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LGL: {
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a + machine->global_offset].float_int / machine->stack[ip->b].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_LGG: {
			machine->stack[ip->c].float_int = machine->stack[ip->a + machine->global_offset].float_int / machine->stack[ip->b].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GLL: {
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int / machine->stack[ip->b + machine->global_offset].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GLG: {
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int / machine->stack[ip->b + machine->global_offset].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GGL: {
			machine->stack[ip->c + machine->global_offset].float_int = machine->stack[ip->a].float_int / machine->stack[ip->b].float_int;
			break;
		}
		case MACHINE_OP_CODE_FLOAT_DIVIDE_GGG: {
			machine->stack[ip->c].float_int = machine->stack[ip->a].float_int / machine->stack[ip->b].float_int;
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
		case MACHINE_OP_CODE_LONG_INCREMENT_L:
			++machine->stack[ip->a + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_INCREMENT_G:
			++machine->stack[ip->a].long_int;
			break;
		case MACHINE_OP_CODE_LONG_DECREMENT_L:
			--machine->stack[ip->a + machine->global_offset].long_int;
			break;
		case MACHINE_OP_CODE_LONG_DECREMENT_G:
			--machine->stack[ip->a].long_int;
			break;
		case MACHINE_OP_CODE_FLOAT_INCREMENT_L:
			++machine->stack[ip->a + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_INCREMENT_G:
			++machine->stack[ip->a].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_DECREMENT_L:
			--machine->stack[ip->a + machine->global_offset].float_int;
			break;
		case MACHINE_OP_CODE_FLOAT_DECREMENT_G:
			--machine->stack[ip->a].float_int;
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
				if (machine->last_err == ERROR_NONE)
					MACHINE_PANIC(ERROR_FOREIGN)
				else
					MACHINE_PANIC(machine->last_err);
			}
			break;
		}
		{
			heap_alloc_t* heap_alloc;
		case MACHINE_OP_CODE_CONFIG_TYPESIG_L:
			heap_alloc = machine->stack[ip->a + machine->global_offset].heap_alloc;
			goto final_config_typesig;
		case MACHINE_OP_CODE_CONFIG_TYPESIG_G:
			heap_alloc = machine->stack[ip->a].heap_alloc;
		final_config_typesig:
			if (ip->c) {
				MACHINE_PANIC_COND(heap_alloc->type_sig = malloc(sizeof(machine_type_sig_t)), ERROR_MEMORY);
				MACHINE_ESCAPE_COND(atomize_heap_type_sig(machine, machine->defined_signatures[ip->b], heap_alloc->type_sig, 1));
			}
			else
				heap_alloc->type_sig = &machine->defined_signatures[ip->b];
			break; 
		}

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
		{
			heap_alloc_t* array_register;
			heap_alloc_t* assign_value;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_ARRAY_LL:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typeguard_protect_array;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_ARRAY_LG:
			array_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
			goto typeguard_protect_array;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_ARRAY_GL:
			array_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typeguard_protect_array;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_ARRAY_GG:
			array_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
		typeguard_protect_array:
			if(array_register->type_sig->sub_types->super_signature >= TYPE_SUPER_ARRAY)
				MACHINE_PANIC_COND(type_signature_match(machine, *assign_value->type_sig, *array_register->type_sig->sub_types), ERROR_UNEXPECTED_TYPE);
			break;
		}
		{
			heap_alloc_t* record_register;
			heap_alloc_t* assign_value;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_LL:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typeguard_protect_typearg_property;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_LG:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
			goto typeguard_protect_typearg_property;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_GL:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typeguard_protect_typearg_property;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_GG:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
		typeguard_protect_typearg_property:
			if(record_register->type_sig->sub_types[ip->c].super_signature >= TYPE_SUPER_ARRAY)
				MACHINE_PANIC_COND(type_signature_match(machine, *assign_value->type_sig, record_register->type_sig->sub_types[ip->c]), ERROR_UNEXPECTED_TYPE);
			break;
		}
		{
			heap_alloc_t* record_register;
			heap_alloc_t* assign_value;
			machine_type_sig_t req_sig;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_DOWNCAST_LL:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typeguard_protect_typearg_property_downcast;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_DOWNCAST_LG:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
			goto typeguard_protect_typearg_property_downcast;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_DOWNCAST_GL:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typeguard_protect_typearg_property_downcast;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_TYPEARG_PROPERTY_DOWNCAST_GG:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
		typeguard_protect_typearg_property_downcast:
			MACHINE_PANIC_COND(atomize_heap_type_sig(machine, *record_register->type_sig, &req_sig, 1), ERROR_MEMORY);
			MACHINE_PANIC_COND(downcast_type_signature(machine, &req_sig, machine->extra_a), ERROR_MEMORY);

			if (req_sig.sub_types[ip->c].super_signature >= TYPE_SUPER_ARRAY && !type_signature_match(machine, *assign_value->type_sig, req_sig.sub_types[ip->c])) {
				free_type_signature(&req_sig);
				MACHINE_PANIC(ERROR_UNEXPECTED_TYPE);
			}
			free_type_signature(&req_sig);
			break;
		}
		{
			heap_alloc_t* record_register;
			heap_alloc_t* assign_value;
			machine_type_sig_t property_type_sig;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_LL:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typearg_protect_sub_property;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_LG:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
			goto typearg_protect_sub_property;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_GL:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typearg_protect_sub_property;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_GG:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
		typearg_protect_sub_property:
			MACHINE_PANIC_COND(atomize_heap_type_sig(machine, machine->defined_signatures[ip->c], &property_type_sig, 0), ERROR_MEMORY);
			MACHINE_PANIC_COND(get_super_type(machine, record_register->type_sig->sub_types, &property_type_sig), ERROR_MEMORY);
			if (!type_signature_match(machine, *assign_value->type_sig, property_type_sig)) {
				free_type_signature(&property_type_sig);
				MACHINE_PANIC(ERROR_UNEXPECTED_TYPE);
			}
			free_type_signature(&property_type_sig);
			break;
		}
		{
			heap_alloc_t* record_register;
			heap_alloc_t* assign_value;
			machine_type_sig_t property_type_sig;
			machine_type_sig_t req_sig;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_DOWNCAST_LL:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typearg_protect_sub_property_downcast;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_DOWNCAST_LG:
			record_register = machine->stack[ip->a + machine->global_offset].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
			goto typearg_protect_sub_property_downcast;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_DOWNCAST_GL:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b + machine->global_offset].heap_alloc;
			goto typearg_protect_sub_property_downcast;
		case MACHINE_OP_CODE_TYPEGUARD_PROTECT_SUB_PROPERTY_DOWNCAST_GG:
			record_register = machine->stack[ip->a].heap_alloc;
			assign_value = machine->stack[ip->b].heap_alloc;
		typearg_protect_sub_property_downcast:
			MACHINE_PANIC_COND(atomize_heap_type_sig(machine, *record_register->type_sig, &req_sig, 1), ERROR_MEMORY);
			MACHINE_PANIC_COND(downcast_type_signature(machine, &req_sig, machine->extra_a), ERROR_MEMORY);

			MACHINE_PANIC_COND(atomize_heap_type_sig(machine, machine->defined_signatures[ip->c], &property_type_sig, 0), ERROR_MEMORY);
			MACHINE_PANIC_COND(get_super_type(machine, req_sig.sub_types, &property_type_sig), ERROR_MEMORY);
			if (!type_signature_match(machine, *assign_value->type_sig, property_type_sig)) {
				free_type_signature(&property_type_sig);
				free_type_signature(&req_sig);
				MACHINE_PANIC(ERROR_UNEXPECTED_TYPE);
			}
			free_type_signature(&property_type_sig);
			free_type_signature(&req_sig);
			break;
		}

		}
		ip++;
	}
	return 1;
}
#undef MACHINE_PANIC_COND
#undef MACHINE_PANIC
#undef MACHINE_ESCAPE_COND