#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include "debug.h"

static const char* opcode_names[] = {
	"abort      ",
	"foreign    ",

	"mov        ",
	"check      ",

	"jmp        ",

	"jmphist    ",
	"jmpback    ",
	"lbl        ",
	
	"ldheap     ",
	"ldheap_i   ",
	"stoheap    ",
	"stoheap_i  ",
	
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
	"insufficient memory",

	"unexpected token",
	"cannot set readonly var",

	"unallowed type",
	"missing type argument",

	"expected sub types",
	"to many sub types",

	"undeclared variable",
	"unexpected type",
	"unexpected argument length",

	"cannot return",
	"cannot break",
	"cannot continue",

	"insufficient position stack",
	"index out of range",
	"stack overflow",
	"read unitialized memory",
	
	"program aborted",
	"foreign error",
	"cannot open file"
};

static void print_instruction(machine_ins_t ins){
	printf("%s a:%" PRIu16 "-%i, b:%" PRIu16 "-%i, c:%" PRIu16 "-%i",opcode_names[ins.op_code], ins.a, ins.a_flag, ins.b, ins.b_flag, ins.c, ins.c_flag);
}

void print_instructions(machine_ins_t* ins, uint16_t ins_count) {
	for (uint_fast16_t i = 0; i < ins_count; i++) {
		printf("%"PRIu16 ": ", i);
		print_instruction(ins[i]);
		printf("\n");
	}
}

const char* get_err_msg(error_t error) {
	return error_names[error];
}