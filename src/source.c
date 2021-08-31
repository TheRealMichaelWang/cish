#include <stdlib.h>
#include <stdio.h>
#include "compiler.h"
#include "debug.h"

int main() {

	machine_t machine;
	compiler_t* compiler = malloc(sizeof(compiler_t));
	init_compiler(compiler, "auto index_at = (array<typearg elemType> arr, int index)typearg elemType { return arr[index]; }; array<int> ints = new int[10]; int elem = index_at(ints, 3);");

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