#pragma once

#ifndef FILE_H
#define FILE_H

#include "machine.h"
#include "ast.h"

machine_ins_t* file_load_ins(char* path, machine_t* machine, uint16_t* instruction_count);
int file_save_compiled(char* path, ast_parser_t* ast_parser, machine_t* machine, machine_ins_t* instructions, uint16_t instruction_count);

char* file_read_source(char* path);

#endif // !FILE_H
