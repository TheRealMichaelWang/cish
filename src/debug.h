#pragma once

#ifndef DEBUG_H
#define DEBUG_H

#include "machine.h"
#include "scanner.h"
#include "error.h"

typedef struct debug_src_loc {
	int row, col;
	char* file_name;

	uint64_t min_ip, max_ip;
} dbg_src_loc_t;

typedef struct debug_table {
	dbg_src_loc_t* src_locations;
	uint64_t src_loc_count, alloced_src_locs;

	safe_gc_t* safe_gc;
} dbg_table_t;

//printing utilities
void print_instructions(machine_ins_t* ins, uint16_t ins_count);
const char* get_err_msg(error_t error);

void print_error_trace(multi_scanner_t multi_scanner);
int print_back_trace(machine_t* machine, dbg_table_t* dbg_table, machine_ins_t* ins_begin);

//debug table related definitions
int init_debug_table(dbg_table_t* dbg_table, safe_gc_t* safe_gc);
void free_debug_table(dbg_table_t* dbg_table);

int debug_table_add_loc(dbg_table_t* dbg_table, multi_scanner_t multi_scanner, uint32_t* output_src_loc_id);
void debug_loc_set_minip(dbg_table_t* dbg_table, uint32_t src_loc_id, uint64_t min_ip);
void debug_loc_set_maxip(dbg_table_t* dbg_table, uint32_t src_loc_id, uint64_t max_ip);

dbg_src_loc_t* dbg_table_find_src_loc(dbg_table_t* dbg_table, uint64_t ip);

#endif // !DEBUG_h
