#pragma once

#ifndef FILE_H
#define FILE_H

#include "machine.h"
#include "ast.h"
#include "error.h"

machine_ins_t* file_load_ins(const char* path, safe_gc_t* safe_gc, machine_t* machine, uint16_t* instruction_count, uint16_t* constant_count, uint16_t* signature_count);
int file_save_compiled(const char* path, ast_t* ast, machine_t* machine, machine_ins_t* instructions, uint16_t instruction_count);

char* file_read_source(const char* path);
char* get_row_str(const char* text, int row);

#endif // !FILE_H
