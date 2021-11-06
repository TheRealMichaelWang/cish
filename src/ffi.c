#include <stdlib.h>
#include "machine.h"
#include "error.h"
#include "ffi.h"

int init_ffi(ffi_t* ffi_table) {
	ESCAPE_ON_FAIL(ffi_table->func_table = malloc((ffi_table->func_alloc = 64) * sizeof(foreign_func)));
	ffi_table->func_count = 0;
	return 1;
}

void free_ffi(ffi_t* ffi_table) {
	free(ffi_table->func_table);
}

int ffi_include_func(ffi_t* ffi_table, foreign_func func) {
	if (ffi_table->func_count == ffi_table->func_alloc) {
		foreign_func* new_table = realloc(ffi_table->func_table, (ffi_table->func_alloc *= 2) * sizeof(foreign_func));
		ESCAPE_ON_FAIL(new_table);
		ffi_table->func_table = new_table;
	}
	ffi_table->func_table[ffi_table->func_count++] = func;
	return 1;
}

int ffi_invoke(ffi_t* ffi_table, machine_t* machine, machine_reg_t* id_reg, machine_reg_t* in_reg, machine_reg_t* out_reg) {
	if (id_reg->long_int >= ffi_table->func_count)
		return 0;
	return ffi_table->func_table[id_reg->long_int](machine, in_reg, out_reg);
}