#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "file.h"
#include "debug.h"

static const char* opcode_names[] = {
	"abort           ",
	"foreign(lll)    ",
	"foreign(llg)    ",
	"foreign(lgl)    ",
	"foreign(lgg)    ",
	"foreign(gll)    ",
	"foreign(glg)    ",
	"foreign(ggl)    ",
	"foreign(ggg)    ",

	"mov(ll)         ",
	"mov(lg)         ",
	"mov(gl)         ",
	"mov(ll)         ",

	"set(l)          ",
	"popatomtsig(l)  ",

	"jmp             ",
	"jmpcheck(l)     ",
	"jmpcheck(g)     ",

	"call(l)         ",
	"call(g)         ",
	"return          ",
	"lbl(l)          ",
	"lbl(g)          ",
	
	"ldalloc(lll)    ",
	"ldalloc(llg)    ",
	"ldalloc(lgl)    ",
	"ldalloc(lgg)    ",
	"ldalloc(gll)    ",
	"ldalloc(glg)    ",
	"ldalloc(ggl)    ",
	"ldalloc(ggg)    ",
	"ldalloc_i(ll)   ",
	"ldalloc_i(lg)   ",
	"ldalloc_i(gl)   ",
	"ldalloc_i(gg)   ",
	"ldalloc_ib(ll)  ",
	"ldalloc_ib(ll)  ",
	"ldalloc_ib(ll)  ",
	"ldalloc_ib(ll)  ",
	"stoalloc(llg)   ",
	"stoalloc(lgl)   ",
	"stoalloc(lgg)   ",
	"stoalloc(gll)   ",
	"stoalloc(gll)   ",
	"stoalloc(glg)   ",
	"stoalloc(ggl)   ",
	"stoalloc(ggg)   ",
	"stoalloc_i(ll)  ",
	"stoalloc_i(lg)  ",
	"stoalloc_i(gl)  ",
	"stoalloc_i(gg)  ",
	"stoalloc_ib(ll) ",
	"stoalloc_ib(lg) ",
	"stoalloc_ib(gl) ",
	"stoalloc_ib(gg) ",
	"conft_i(l)      ",
	"conft_i(g)      ",
	"dynconft_i(ll)  ",
	"dynconft(ll)    ",
	
	"offset          ",
	"deoffset        ",

	"alloc(ll)       ",
	"alloc(lg)       ",
	"alloc(gl)       ",
	"alloc(gg)       ",
	"alloc_i(l)      ",
	"alloc_i(g)      ",
	"free(l)         ",
	"free(g)         ",
	"dynfree(ll)     ",

	"newframe        ",
	"gctrace(l)      ",
	"gctrace(g)      ",
	"dyntrace(ll)    ",
	"gcclean         ",

	"and(lll)        ",
	"and(llg)        ",
	"and(lgl)        ",
	"and(lgg)        ",
	"and(gll)        ",
	"and(glg)        ",
	"and(ggl)        ",
	"and(ggg)        ",
	"or(lll)         ",
	"or(llg)         ",
	"or(lgl)         ",
	"or(lgg)         ",
	"or(gll)         ",
	"or(glg)         ",
	"or(ggl)         ",
	"or(ggg)         ",
	"not(ll)         ",
	"not(lg)         ",
	"not(gl)         ",
	"not(gg)         ",
	"len(ll)         ",
	"len(lg)         ",
	"len(gl)         ",
	"len(gg)         ",

	"ptrequal(lll)   ",
	"ptrequal(llg)   ",
	"ptrequal(lgl)   ",
	"ptrequal(lgg)   ",
	"ptrequal(gll)   ",
	"ptrequal(glg)   ",
	"ptrequal(ggl)   ",
	"ptrequal(ggg)   ",
	"bequal(lll)     ",
	"bequal(llg)     ",
	"bequal(lgl)     ",
	"bequal(lgg)     ",
	"bequal(gll)     ",
	"bequal(glg)     ",
	"bequal(ggl)     ",
	"bequal(ggg)     ",
	"cequal(lll)     ",
	"cequal(llg)     ",
	"cequal(lgl)     ",
	"cequal(lgg)     ",
	"cequal(gll)     ",
	"cequal(glg)     ",
	"cequal(ggl)     ",
	"cequal(ggg)     ",
	"lequal(lll)     ",
	"lequal(llg)     ",
	"lequal(lgl)     ",
	"lequal(lgg)     ",
	"lequal(gll)     ",
	"lequal(glg)     ",
	"lequal(ggl)     ",
	"lequal(ggg)     ",
	"fequal(lll)     ",
	"fequal(llg)     ",
	"fequal(lgl)     ",
	"fequal(lgg)     ",
	"fequal(gll)     ",
	"fequal(glg)     ",
	"fequal(ggl)     ",
	"fequal(ggg)     ",
	
	"lmore(lll)      ",
	"lmore(llg)      ",
	"lmore(lgl)      ",
	"lmore(lgg)      ",
	"lmore(gll)      ",
	"lmore(glg)      ",
	"lmore(ggl)      ",
	"lmore(ggg)      ",
	"lless(lll)      ",
	"lless(llg)      ",
	"lless(lgl)      ",
	"lless(lgg)      ",
	"lless(gll)      ",
	"lless(glg)      ",
	"lless(ggl)      ",
	"lless(ggg)      ",
	"lmoreeq(lll)    ",
	"lmoreeq(llg)    ",
	"lmoreeq(lgl)    ",
	"lmoreeq(lgg)    ",
	"lmoreeq(gll)    ",
	"lmoreeq(glg)    ",
	"lmoreeq(ggl)    ",
	"lmoreeq(ggg)    ",
	"llesseq(lll)    ",
	"llesseq(llg)    ",
	"llesseq(lgl)    ",
	"llesseq(lgg)    ",
	"llesseq(gll)    ",
	"llesseq(glg)    ",
	"llesseq(ggl)    ",
	"llesseq(ggg)    ",

	"ladd(lll)       ",
	"ladd(llg)       ",
	"ladd(lgl)       ",
	"ladd(lgg)       ",
	"ladd(gll)       ",
	"ladd(glg)       ",
	"ladd(ggl)       ",
	"ladd(ggg)       ",
	"lsub(lll)       ",
	"lsub(llg)       ",
	"lsub(lgl)       ",
	"lsub(lgg)       ",
	"lsub(gll)       ",
	"lsub(glg)       ",
	"lsub(ggl)       ",
	"lsub(ggg)       ",
	"lmul(lll)       ",
	"lmul(llg)       ",
	"lmul(lgl)       ",
	"lmul(lgg)       ",
	"lmul(gll)       ",
	"lmul(glg)       ",
	"lmul(ggl)       ",
	"lmul(ggg)       ",
	"ldiv(lll)       ",
	"ldiv(llg)       ",
	"ldiv(lgl)       ",
	"ldiv(lgg)       ",
	"ldiv(gll)       ",
	"ldiv(glg)       ",
	"ldiv(ggl)       ",
	"ldiv(ggg)       ",
	"lmod(lll)       ",
	"lmod(llg)       ",
	"lmod(lgl)       ",
	"lmod(lgg)       ",
	"lmod(gll)       ",
	"lmod(glg)       ",
	"lmod(ggl)       ",
	"lmod(ggg)       ",
	"lpow(lll)       ",
	"lpow(llg)       ",
	"lpow(lgl)       ",
	"lpow(lgg)       ",
	"lpow(gll)       ",
	"lpow(glg)       ",
	"lpow(ggl)       ",
	"lpow(ggg)       ",

	"fmore(lll)      ",
	"fmore(llg)      ",
	"fmore(lgl)      ",
	"fmore(lgg)      ",
	"fmore(gll)      ",
	"fmore(glg)      ",
	"fmore(ggl)      ",
	"fmore(ggg)      ",
	"fless(lll)      ",
	"fless(llg)      ",
	"fless(lgl)      ",
	"fless(lgg)      ",
	"fless(gll)      ",
	"fless(glg)      ",
	"fless(ggl)      ",
	"fless(ggg)      ",
	"fmoreeq(lll)    ",
	"fmoreeq(llg)    ",
	"fmoreeq(lgl)    ",
	"fmoreeq(lgg)    ",
	"fmoreeq(gll)    ",
	"fmoreeq(glg)    ",
	"fmoreeq(ggl)    ",
	"fmoreeq(ggg)    ",
	"flesseq(lll)    ",
	"flesseq(llg)    ",
	"flesseq(lgl)    ",
	"flesseq(lgg)    ",
	"flesseq(gll)    ",
	"flesseq(glg)    ",
	"flesseq(ggl)    ",
	"flesseq(ggg)    ",

	
	"fadd(lll)       ",
	"fadd(llg)       ",
	"fadd(lgl)       ",
	"fadd(lgg)       ",
	"fadd(gll)       ",
	"fadd(glg)       ",
	"fadd(ggl)       ",
	"fadd(ggg)       ",
	"fsub(lll)       ",
	"fsub(llg)       ",
	"fsub(lgl)       ",
	"fsub(lgg)       ",
	"fsub(gll)       ",
	"fsub(glg)       ",
	"fsub(ggl)       ",
	"fsub(ggg)       ",
	"fmul(lll)       ",
	"fmul(llg)       ",
	"fmul(lgl)       ",
	"fmul(lgg)       ",
	"fmul(gll)       ",
	"fmul(glg)       ",
	"fmul(ggl)       ",
	"fmul(ggg)       ",
	"fdiv(lll)       ",
	"fdiv(llg)       ",
	"fdiv(lgl)       ",
	"fdiv(lgg)       ",
	"fdiv(gll)       ",
	"fdiv(glg)       ",
	"fdiv(ggl)       ",
	"fdiv(ggg)       ",
	"fmod(lll)       ",
	"fmod(llg)       ",
	"fmod(lgl)       ",
	"fmod(lgg)       ",
	"fmod(gll)       ",
	"fmod(glg)       ",
	"fmod(ggl)       ",
	"fmod(ggg)       ",
	"fpow(lll)       ",
	"fpow(llg)       ",
	"fpow(lgl)       ",
	"fpow(lgg)       ",
	"fpow(gll)       ",
	"fpow(glg)       ",
	"fpow(ggl)       ",
	"fpow(ggg)       ",

	"fneg(ll)        ",
	"fneg(lg)        ",
	"fneg(gl)        ",
	"fneg(gg)        ",
	"lneg(ll)        ",
	"lneg(lg)        ",
	"lneg(gl)        ",
	"lneg(gg)        ",
	"linc(l)         ",
	"linc(g)         ",
	"ldec(l)         ",
	"ldec(g)         ",
	"finc(l)         ",
	"finc(g)         ",
	"fdec(l)         ",
	"fdec(g)         ",

	"relate type     ",
	"configtypesig(l)",
	"configtypesig(g)",
	"rt-typecheck(ll)",
	"rt-typecheck(lg)",
	"rt-typecheck(gl)",
	"rt-typecheck(gg)",
	"rt-typecast(ll) ",
	"rt-typecast(lg) ",
	"rt-typecast(gl) ",
	"rt-typecast(gg) ",
	"dtypecheck(ddl) ",
	"dtypecheck(ddg) ",
	"dtypecheck(drl) ",
	"dtypecheck(drg) ",
	"dtypecheck(rdl) ",
	"dtypecheck(rdg) ",
	"dtypecast(ddl)  ",
	"dtypecast(ddg)  ",
	"dtypecast(drl)  ",
	"dtypecast(drg)  ",
	"dtypecast(rdl)  ",
	"dtypecast(rdg)  ",
};

static const char* error_names[] = {
	"none",
	"memory",
	"internal",

	"unexpected token",

	"cannot set readonly var",
	"unallowed type",

	"undeclared",
	"redeclaration",

	"unexpected type",
	"unexpected argument length",

	"cannot return",
	"cannot break",
	"cannot continue",
	"cannot extend(is final)",
	"cannot initialize(is abstract)",

	"index out of range",
	"divide by zero",
	"stack overflow",
	"read unitialized memory",

	"function unable to return",
	
	"program aborted",
	"foreign error",
	"cannot open file"
};

void print_instructions(machine_ins_t* ins, uint16_t ins_count) {
	for (uint16_t i = 0; i < ins_count; i++)
		printf("%"PRIu16 ":\t%s\t%" PRIu16 "\t%" PRIu16 "\t%" PRIu16 "\n", i, opcode_names[ins[i].op_code], ins[i].a, ins[i].b, ins[i].c);
}

const char* get_err_msg(error_t error) {
	return error_names[error];
}

void print_error_trace(multi_scanner_t multi_scanner) {
	if (multi_scanner.current_file) {
		for (uint_fast8_t i = 0; i < multi_scanner.current_file; i++)
			printf("in %s: row %" PRIu32 ", col %"PRIu32 "\n", multi_scanner.file_paths[i], multi_scanner.scanners[i].row, multi_scanner.scanners[i].col);
		putchar('\t');
	}
	if (multi_scanner.last_tok.type == TOK_EOF) {
		printf("Error Occured at EOF");
	}
	else {
		for (uint_fast32_t i = 0; i < multi_scanner.last_tok.length; i++)
			printf("%c", multi_scanner.last_tok.str[i]);
		for (uint_fast8_t i = multi_scanner.last_tok.length; multi_scanner.last_tok.str[i] && multi_scanner.last_tok.str[i] != '\n'; i++)
			printf("%c", multi_scanner.last_tok.str[i]);
	}
	putchar('\n');
}

int print_back_trace(machine_t* machine, dbg_table_t* dbg_table, machine_ins_t* ins_begin) {
	puts("Traceback (most recent call last):");
	for (uint_fast16_t i = 0; i < machine->position_count; i++) {
		dbg_src_loc_t* src_loc = dbg_table_find_src_loc(dbg_table, machine->positions[i] - ins_begin);
		ESCAPE_ON_FAIL(src_loc);
		printf("\tCall from \"%s\", row %i, col %i\n", src_loc->file_name, src_loc->row, src_loc->col);
	}
	dbg_src_loc_t* src_loc_fin = dbg_table_find_src_loc(dbg_table, machine->last_err_ip);
	ESCAPE_ON_FAIL(src_loc_fin);

	char* code_src = file_read_source(src_loc_fin->file_name);
	ESCAPE_ON_FAIL(code_src);

	printf("At \"%s\", row %i, col %i\n\t", src_loc_fin->file_name, src_loc_fin->row, src_loc_fin->col);
	char* line = get_row_str(code_src, src_loc_fin->row - 1);
	if (!line) {
		free(code_src);
		return 0;
	}

	printf("%s\n\t", line);
	for (int i = 1; i < src_loc_fin->col; i++) {
		if (line[i - 1] == '\t')
			putchar('\t');
		else
			putchar(' ');
	}
	puts("^");

	free(line);
	free(code_src);
	return 1;
}

int init_debug_table(dbg_table_t* dbg_table, safe_gc_t* safe_gc) {
	dbg_table->src_loc_count = 0;
	dbg_table->safe_gc = safe_gc;

	ESCAPE_ON_FAIL(dbg_table->src_locations = safe_transfer_malloc(safe_gc, (dbg_table->alloced_src_locs = 32) * sizeof(dbg_src_loc_t)));
	return 1;
}

void free_debug_table(dbg_table_t* dbg_table) {
	for (dbg_src_loc_t* current_loc = &dbg_table->src_locations[0]; current_loc != &dbg_table->src_locations[dbg_table->src_loc_count]; current_loc++)
		free(current_loc->file_name);
	free(dbg_table->src_locations);
}

int debug_table_add_loc(dbg_table_t* dbg_table, multi_scanner_t multi_scanner, uint32_t* output_src_loc_id) {
	if (dbg_table->src_loc_count == dbg_table->alloced_src_locs)
		ESCAPE_ON_FAIL(dbg_table->src_locations = safe_realloc(dbg_table->safe_gc, dbg_table->src_locations, (dbg_table->alloced_src_locs += 16) * sizeof(dbg_src_loc_t)));
	dbg_src_loc_t* src_loc = &dbg_table->src_locations[*output_src_loc_id = dbg_table->src_loc_count++];

	const char* file_name = multi_scanner.file_paths[multi_scanner.current_file - 1];
	ESCAPE_ON_FAIL(src_loc->file_name = safe_transfer_malloc(dbg_table->safe_gc, (strlen(file_name) + 1) * sizeof(char)));
	strcpy(src_loc->file_name, file_name);
	src_loc->row = multi_scanner.scanners[multi_scanner.current_file - 1].row;
	src_loc->col = multi_scanner.scanners[multi_scanner.current_file - 1].col;
	src_loc->min_ip = UINT64_MAX;
	src_loc->max_ip = 0;
	return 1;
}

void debug_loc_set_minip(dbg_table_t* dbg_table, uint32_t src_loc_id, uint64_t min_ip) {
	if (min_ip < dbg_table->src_locations[src_loc_id].min_ip)
		dbg_table->src_locations[src_loc_id].min_ip = min_ip;
}

void debug_loc_set_maxip(dbg_table_t* dbg_table, uint32_t src_loc_id, uint64_t max_ip) {
	if (max_ip > dbg_table->src_locations[src_loc_id].max_ip)
		dbg_table->src_locations[src_loc_id].max_ip = max_ip;
}

dbg_src_loc_t* dbg_table_find_src_loc(dbg_table_t* dbg_table, uint64_t ip) {
	dbg_src_loc_t* src_loc = NULL;
	uint64_t diff = UINT64_MAX;

	for (dbg_src_loc_t* current_loc = &dbg_table->src_locations[0]; current_loc != &dbg_table->src_locations[dbg_table->src_loc_count]; current_loc++)
		if (ip >= current_loc->min_ip && ip < current_loc->max_ip) {
			uint64_t loc_range = current_loc->max_ip - current_loc->min_ip;
			if (loc_range < diff) {
				diff = loc_range;
				src_loc = current_loc;
			}
		}

	return src_loc;
}