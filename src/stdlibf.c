#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <time.h>
#include <ctype.h>
#include "error.h"
#include "ffi.h"
#include "stdlibf.h"

static char* read_str_from_heap_alloc(heap_alloc_t* heap_alloc) {
	char* buffer = malloc(heap_alloc->limit + 1);
	ESCAPE_ON_FAIL(buffer);
	for (int i = 0; i < heap_alloc->limit; i++)
		buffer[i] = heap_alloc->registers[i].char_int;
	buffer[heap_alloc->limit] = 0;
	return buffer;
}

static int std_itof(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->float_int = (float)in->long_int;
	return 1;
}

static int std_floor(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->long_int = (uint64_t)floor(in->float_int);
	return 1;
}

static int std_ceil(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->long_int = (uint64_t)ceil(in->float_int);
	return 1;
}

static int std_round(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->long_int = (uint64_t)round(in->float_int);
	return 1;
}

static int std_ftos(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char output[50];
	sprintf(output, "%f", in->float_int);
	uint8_t len = strlen(output);
	out->heap_alloc = machine_alloc(machine, len, GC_TRACE_MODE_NONE);
	for (uint_fast8_t i = 0; i < len; i++) {
		out->heap_alloc->registers[i].char_int = output[i];
		out->heap_alloc->init_stat[i] = 1;
	}
	return 1;
}

static int std_stof(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char* buffer = read_str_from_heap_alloc(in->heap_alloc);
	PANIC_ON_FAIL(buffer, machine, ERROR_MEMORY);
	char* ferror;
	out->float_int = strtod(buffer, &ferror);

	if (ferror && !isspace((unsigned char)*ferror))
		out->float_int = nan("");

	free(buffer);
	return 1;
}

static int std_itos(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char output[50];
	sprintf(output, "%" PRIi64, in->long_int);
	uint8_t len = strlen(output);
	ESCAPE_ON_FAIL(out->heap_alloc = machine_alloc(machine, len, GC_TRACE_MODE_NONE));
	for (uint_fast8_t i = 0; i < len; i++) {
		out->heap_alloc->registers[i].char_int = output[i];
		out->heap_alloc->init_stat[i] = 1;
	}
	return 1;
}

static int std_stoi(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char* buffer = read_str_from_heap_alloc(in->heap_alloc);
	PANIC_ON_FAIL(buffer, machine, ERROR_MEMORY);
	out->long_int = strtol(buffer, NULL, 10);
	free(buffer);
	return 1;
}

static int std_ctoi(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->long_int = in->char_int;
	return 1;
}

static int std_itoc(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->char_int = in->long_int;
	return 1;
}

static int std_out(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	printf("%c", in->char_int);
	return 1;
}

static int std_in(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	return scanf("%c", &out->char_int);
}

static int std_random(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->long_int = rand();
	return 1;
}

static int std_sin(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->float_int = sin(in->float_int);
	return 1;
}

static int std_cos(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->float_int = cos(in->float_int);
	return 1;
}

static int std_tan(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->float_int = tan(in->float_int);
	return 1;
}

static int std_time(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->long_int = time(0);
	return 1;
}

static int std_import(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char* import_name = read_str_from_heap_alloc(in->heap_alloc);
	PANIC_ON_FAIL(import_name, machine, ERROR_MEMORY);
	out->long_int = machine->ffi_table.func_count;
	if (!dynamic_library_load(machine->dynamic_library_table, machine, import_name)) {
		out->long_int = -1;
	}
	return 1;
}

static int std_calloc(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	out->heap_alloc = machine_alloc(machine, in->long_int, GC_TRACE_MODE_NONE);
	for (uint_fast16_t i = 0; i < out->heap_alloc->limit; i++) {
		out->heap_alloc->registers[i].long_int = 0;
		out->heap_alloc->init_stat[i] = 1;
	}
	return 1;
}

int install_stdlib(machine_t* machine) {
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_itof));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_floor));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_ceil));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_round));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_ftos));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_stof));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_itos));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_stoi));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_out));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_in));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_random));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_sin));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_cos));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_tan));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_itoc));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_ctoi));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_time));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_import));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, std_calloc));
	return 1;
}