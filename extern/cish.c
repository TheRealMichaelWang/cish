#include <stdlib.h>
#include "cish.h"

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

heap_alloc_t* machine_alloc(machine_t* machine, uint16_t req_size, int child_is_reftype) {
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
	heap_alloc->trace_mode = child_is_reftype ? GC_TRACE_MODE_ALL : GC_TRACE_MODE_NONE;
	heap_alloc->type_sig = NULL;
	PANIC_ON_FAIL(heap_alloc, machine, ERROR_MEMORY);
	if (req_size) {
		PANIC_ON_FAIL(heap_alloc->registers = malloc(req_size * sizeof(machine_reg_t)), machine, ERROR_MEMORY);
		PANIC_ON_FAIL(heap_alloc->init_stat = calloc(req_size, sizeof(int)), machine, ERROR_MEMORY);
	}
	return heap_alloc;
#undef CHECK_HEAP_COUNT
}