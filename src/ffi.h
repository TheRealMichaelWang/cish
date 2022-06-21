#pragma once

#ifndef FOREIGN_H
#define FOREIGN_H

#include <stdint.h>

typedef struct machine machine_t;
typedef union machine_register machine_reg_t;
typedef int (*foreign_func)(machine_t* machine, machine_reg_t* input, machine_reg_t* output);
typedef int (*cish_dll_entry)(machine_t* machine);

typedef struct foreign_func_table {
    foreign_func* func_table;
    uint16_t func_count, func_alloc;
} ffi_t;

int init_ffi(ffi_t* ffi_table);
void free_ffi(ffi_t* ffi_table);

int ffi_include_func(ffi_t* ffi_table, foreign_func func);
int ffi_invoke(ffi_t* ffi_table, machine_t* machine, machine_reg_t* id_reg, machine_reg_t* in_reg, machine_reg_t* out_reg);

typedef struct dynamic_library {
    char* name;
    cish_dll_entry entry_point;
    void* handle;
} dynamic_library_t;

typedef struct dynamic_library_table {
    dynamic_library_t* imported_libs;

    uint8_t imported_lib_count;
} dynamic_library_table_t;

int dynamic_library_init(dynamic_library_table_t* dynamic_library);
void dynamic_library_free(dynamic_library_table_t* dynamic_library);

int dynamic_library_load(dynamic_library_table_t* dynamic_library, machine_t* machine, char* name);

#endif // !FOREIGN_H