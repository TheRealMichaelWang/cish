#pragma once

#ifndef DEBUG_H
#define DEBUG_H

#include "machine.h"
#include "scanner.h"
#include "error.h"

const char* get_err_msg(error_t error);

void print_error_trace(multi_scanner_t multi_scanner);

#endif // !DEBUG_h
