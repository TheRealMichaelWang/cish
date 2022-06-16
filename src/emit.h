#pragma once

#ifndef EMIT_H
#define EMIT_H

#include <stdint.h>
#include <stdio.h>
#include "error.h"
#include "machine.h"
#include "compiler.h"
#include "ast.h"
#include "labels.h"

int emit_c_header(FILE* fileout, int robo_mode);
void emit_constants(FILE* file_out, ast_t* ast, machine_t* machine);
int emit_init(FILE* file_out, ast_t* ast, machine_t* machine);
int emit_instructions(FILE* file_out, label_buf_t* label_buf, compiler_ins_t* instructions, uint64_t count, int dbg);
void emit_final(FILE* file_out, int robo_mode, const char* input_file);
#endif // !EMIT_H
