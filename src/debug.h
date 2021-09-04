#pragma once

#ifndef DEBUG_H
#define DEBUG_H

#include "machine.h"
#include "compiler.h"
#include "error.h"

void print_instructions(machine_ins_t* ins, uint16_t ins_count);
const char* get_err_msg(error_t error);

void print_compiler_err(compiler_t* error_compiler);

#endif // !DEBUG_h
