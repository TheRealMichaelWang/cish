#pragma once

#ifndef FOREIGN_H
#define FOREIGN_H

#include <stdint.h>

typedef union machine_register machine_reg_t;
typedef const int (*foreign_func)(machine_reg_t* input, machine_reg_t* output);

typedef struct foreign_func_table {
	foreign_func* func_table;
	uint16_t func_count, func_alloc;
} ffi_t;

const int init_ffi(ffi_t* ffi_table);
void free_ffi(ffi_t* ffi_table);

const int ffi_include_func(ffi_t* ffi_table, foreign_func func);
const int ffi_invoke(ffi_t* ffi_table, machine_reg_t* id_reg, machine_reg_t* in_reg, machine_reg_t* out_reg);

#endif // !FOREIGN_H