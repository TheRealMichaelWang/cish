#include <stdlib.h>
#include "superforth.h"

#define PANIC(OBJ, ERROR){ OBJ->last_err = ERROR; return 0; }
#define ESCAPE_ON_FAIL(PTR) {if(!(PTR)) { return 0; }}
#define PANIC_ON_FAIL(PTR, OBJ, ERROR) {if(!(PTR)) PANIC(OBJ, ERROR)}

int ffi_include_func(ffi_t* ffi_table, foreign_func func) {
	if (ffi_table->func_count == ffi_table->func_alloc) {
		foreign_func* new_table = realloc(ffi_table->func_table, (ffi_table->func_alloc *= 2) * sizeof(foreign_func));
		ESCAPE_ON_FAIL(new_table);
		ffi_table->func_table = new_table;
	}
	ffi_table->func_table[ffi_table->func_count++] = func;
	return 1;
}

heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, gc_trace_mode_t trace_mode) {
	if (machine->heap_count == machine->heap_alloc_limit)
		PANIC(machine, ERROR_STACK_OVERFLOW);
	heap_alloc_t* heap_alloc;
	if (machine->freed_heap_count) {
		heap_alloc = machine->freed_heap_allocs[--machine->freed_heap_count];
		if (!heap_alloc->reg_with_table)
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
	PANIC_ON_FAIL(heap_alloc, machine, ERROR_MEMORY);
	PANIC_ON_FAIL(heap_alloc->registers = malloc(req_size * sizeof(machine_reg_t)), machine, ERROR_MEMORY);
	PANIC_ON_FAIL(heap_alloc->init_stat = calloc(req_size, sizeof(int)), machine, ERROR_MEMORY);
	if (trace_mode == GC_TRACE_MODE_SOME)
		PANIC_ON_FAIL(heap_alloc->trace_stat = malloc(req_size * sizeof(int)), machine, ERROR_MEMORY);
	return heap_alloc;
}

int free_alloc(machine_t* machine, heap_alloc_t* heap_alloc) {
	if (heap_alloc->pre_freed)
		return 1;
	heap_alloc->pre_freed = 1;

	switch (heap_alloc->trace_mode) {
	case GC_TRACE_MODE_ALL:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i])
				ESCAPE_ON_FAIL(free_alloc(machine, heap_alloc->registers[i].heap_alloc));
		break;
	case GC_TRACE_MODE_SOME:
		for (uint_fast16_t i = 0; i < heap_alloc->limit; i++)
			if (heap_alloc->init_stat[i] && heap_alloc->trace_stat[i])
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