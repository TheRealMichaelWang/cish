#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include "error.h"
#include "ffi.h"
#include "stdlib.h"

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
	out->heap_alloc = machine_alloc(machine, len, GC_NO_TRACE);
	for (uint_fast8_t i = 0; i < len; i++) {
		out->heap_alloc->registers[i].char_int = output[i];
		out->heap_alloc->init_stat[i] = 1;
	}
	return 1;
}

static int std_stof(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char* buffer = malloc(in->heap_alloc->limit + 1);
	ESCAPE_ON_FAIL(buffer);
	for (uint_fast16_t i = 0; i < in->heap_alloc->limit; i++) {
		ESCAPE_ON_FAIL(in->heap_alloc->init_stat[i]);
		buffer[i] = in->heap_alloc->registers[i].char_int;
	}
	out->float_int = strtod(buffer, NULL);
	free(buffer);
	return 1;
}

static int std_itos(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char output[50];
	sprintf(output, "%" PRIi64, in->long_int);
	uint8_t len = strlen(output);
	ESCAPE_ON_FAIL(out->heap_alloc = machine_alloc(machine, len, GC_NO_TRACE));
	for (uint_fast8_t i = 0; i < len; i++) {
		out->heap_alloc->registers[i].char_int = output[i];
		out->heap_alloc->init_stat[i] = 1;
	}
	return 1;
}

static int std_stoi(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	char* buffer = malloc(in->heap_alloc->limit + 1);
	ESCAPE_ON_FAIL(buffer);
	for (uint_fast16_t i = 0; i < in->heap_alloc->limit; i++) {
		ESCAPE_ON_FAIL(in->heap_alloc->init_stat[i]);
		buffer[i] = in->heap_alloc->registers[i].char_int;
	}
	out->long_int = strtol(buffer, NULL, 10);
	free(buffer);
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

void install_stdlib(machine_t* machine) {
	ffi_include_func(&machine->ffi_table, std_itof);
	ffi_include_func(&machine->ffi_table, std_floor);
	ffi_include_func(&machine->ffi_table, std_ceil);
	ffi_include_func(&machine->ffi_table, std_round);
	ffi_include_func(&machine->ffi_table, std_ftos);
	ffi_include_func(&machine->ffi_table, std_stof);
	ffi_include_func(&machine->ffi_table, std_itos);
	ffi_include_func(&machine->ffi_table, std_stoi);
	ffi_include_func(&machine->ffi_table, std_out);
	ffi_include_func(&machine->ffi_table, std_in);
	ffi_include_func(&machine->ffi_table, std_random);
}
