#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include "debug.h"

static const char* opcode_names[] = {
	"abort      ",
	"foreign    ",

	"mov        ",

	"jmp        ",
	"jmpcheck   ",

	"call       ",
	"return     ",
	"lbl        ",
	
	"ldheap     ",
	"ldheap_i   ",
	"ldheap_ib  ",
	"stoheap    ",
	"stoheap_i  ",
	"stoheap_ib",
	"conft_i    ",
	
	"offset     ",
	"deoffset   ",

	"heapalloc  ",
	"heapalloc_i",

	"newframe   ",
	"heaptrace  ",
	"heapclean  ",

	"and        ",
	"or         ",
	"not        ",
	"len        ",

	"bequal     ",
	"cequal     ",
	"lequal     ",
	"fequal     ",

	"lmore      ",
	"lless      ",
	"lmoreeq    ",
	"llesseq    ",

	"ladd       ",
	"lsub       ",
	"lmul       ",
	"ldiv       ",
	"lmod       ",
	"lpow       ",

	"fmore      ",
	"fless      ",
	"fmoreeq    ",
	"flesseq    ",

	"fadd       ",
	"fsub       ",
	"fmul       ",
	"fdiv       ",
	"fmod       ",
	"fpow       ",

	"fneg       ",
	"lneg       ",

	"ltf        ",
	"ftl        "
};

static const char* error_names[] = {
	"none",
	"memory",
	"internal",

	"unexpected token",

	"cannot set readonly var",
	"unallowed type",

	"expected sub types",

	"undeclared",
	"redeclaration",

	"unexpected type",
	"unexpected argument length",

	"cannot return",
	"cannot break",
	"cannot continue",

	"index out of range",
	"stack overflow",
	"read unitialized memory",
	
	"program aborted",
	"foreign error",
	"cannot open file"
};

static void print_register(uint16_t loc, uint8_t offset) {
	printf("\t%" PRIu16, loc);
	printf(offset ? "l" : "g");
}

static void print_instruction(machine_ins_t ins){
	printf("%s" ,opcode_names[ins.op_code]);
	print_register(ins.a, ins.a_flag);
	print_register(ins.b, ins.b_flag);
	print_register(ins.c, ins.c_flag);
}

void print_instructions(machine_ins_t* ins, uint16_t ins_count) {
	for (uint_fast16_t i = 0; i < ins_count; i++) {
		printf("%"PRIu16 ":\t", i);
		print_instruction(ins[i]);
		printf("\n");
	}
}

const char* get_err_msg(error_t error) {
	return error_names[error];
}

void print_error_trace(multi_scanner_t multi_scanner) {
	for (uint_fast8_t i = 0; i < multi_scanner.current_file; i++)
		printf("in %s: row %" PRIu32 ", col %"PRIu32 "\n", multi_scanner.file_paths[i], multi_scanner.scanners[i].row, multi_scanner.scanners[i].col);
	printf("\t");
	for (uint_fast32_t i = 0; i < multi_scanner.last_tok.length; i++)
		if(multi_scanner.last_tok.str[i] != '\n')
			printf("%c", multi_scanner.last_tok.str[i]);
	for(uint_fast8_t i = multi_scanner.last_tok.length; multi_scanner.last_tok.str[i] && multi_scanner.last_tok.str[i] == '\n'; i++)
		printf("%c", multi_scanner.last_tok.str[i]);
	printf("\n");
}