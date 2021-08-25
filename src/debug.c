#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include "debug.h"

static const char* opcode_names[] = {
	"abort      ",
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

	"ltf        "
};

static void print_instruction(machine_ins_t ins){
	printf("%s a:%" PRIu64 "-%i, b:%" PRIu64 "-%i, c:%" PRIu64 "-%i",opcode_names[ins.op_code], ins.a, ins.a_flag, ins.b, ins.b_flag, ins.c, ins.c_flag);
}

void print_instructions(machine_ins_t* ins, uint64_t ins_count) {
	for (uint64_t i = 0; i < ins_count; i++) {
		printf("%"PRIu64 ": ", i);
		print_instruction(ins[i]);
		printf("\n");
	}
}