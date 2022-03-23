#pragma once

#ifndef FILE_H
#define FILE_H

#include "machine.h"
#include "ast.h"

machine_ins_t* file_load_ins(const char* path, machine_t* machine, uint16_t* instruction_count);
int file_save_compiled(const char* path, ast_t* ast, machine_t* machine, machine_ins_t* instructions, uint16_t instruction_count);

char* file_read_source(const char* path);

#endif // !FILE_H
