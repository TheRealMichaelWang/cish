#include <stdlib.h>
#include <stdio.h>
#include "compiler.h"
#include "debug.h"

int main() {

	machine_t machine;
	compiler_t* compiler = malloc(sizeof(compiler_t));
	init_compiler(compiler, "global array<int> arr = new int[10]; auto alloc = int(int n) { if(n == 0) { return 0; } arr = new int[n]; return thisproc(n - 1); }; alloc(5);");

	machine_ins_t* instructions;
	uint64_t instruction_count;
	compile(compiler, &machine, &instructions, &instruction_count);
	
	print_instructions(instructions, instruction_count);

	machine_execute(&machine, instructions, instruction_count);

	free(instructions);
	free_machine(&machine);
	free_compiler(compiler);
	free(compiler);
	return 0;
}