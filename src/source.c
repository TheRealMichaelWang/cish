#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "compiler.h"
#include "machine.h"
#include "file.h"
#include "debug.h"

#define PANIC(MSG) {printf(MSG); exit(EXIT_FAILURE);}

#define READ_ARG argv[current_arg++]
#define EXPECT_FLAG(FLAG) if(strcmp(READ_ARG, FLAG)) { PANIC(("Unexpected flag %s.", FLAG)); }

int main(int argc, const char* argv[]) {
	int current_arg = 0;

	const char* working_dir = READ_ARG;

	while (current_arg < argc)
	{
		const char* flag = READ_ARG;

		if (!strcmp(flag, "-info")) {
			printf("SuperForth 0.1\n"
				"written by Michael Wang, 2020-2021\n"
				"This is free software; see the source for copying conditions. There is NO\n"
				"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
		}
		else if (!strcmp(flag, "-help")) {
			printf("usage: [option flag] -s [source file] -o[output file]\n\n"
				"Valid Option Flags:\n"
				"-cr  Compile and run.\n"
				"-c   Compile and save.\n"
				"-r   Load and run.");
		}
		else if (!strcmp(flag, "-r")) {
			machine_t machine;
			uint16_t instruction_count;

			EXPECT_FLAG("-s");
			machine_ins_t* instructions = file_load_ins(READ_ARG, &machine, &instruction_count);
			if (!instructions)
				PANIC("Error reading instructions.");

			if (!machine_execute(&machine, instructions, instruction_count))
				PANIC(("A runtime error occured(%s).", get_err_msg(machine.last_err)));

			free_machine(&machine);
			free(instructions);
		}
		else if (!strcmp(flag, "-c") || !strcmp(flag, "-cr")) {
			compiler_t* compiler = malloc(sizeof(compiler_t));
			if (!compiler)
				PANIC("Error allocating memory for the compiler.");

			EXPECT_FLAG("-s");
			char* source = file_read_source(READ_ARG);
			if (!source)
				PANIC("Error reading input source file(-s).");

			if (!init_compiler(compiler, source)) {
				print_compiler_err(compiler);
				free_compiler(compiler);
				free(compiler);
				exit(EXIT_FAILURE);
			}
			free(source);
			machine_t machine;
			machine_ins_t* instructions;
			uint16_t instruction_count;
			if (!compile(compiler, &machine, &instructions, &instruction_count)) {
				free_compiler(compiler);
				free_machine(&machine);
				free(instructions);
				free(compiler);
				PANIC(("A compiler error occured(%s).", get_err_msg(compiler->last_err)))
			}

			if (!strcmp(flag, "-c")) {
				EXPECT_FLAG("-o");
				if (!file_save_compiled(READ_ARG, compiler, &machine, instructions, instruction_count))
					PANIC("Error writing instructions to output.");
			}
			else {
				if(!machine_execute(&machine, instructions, instruction_count))
					PANIC(("A runtime error occured(%s)", get_err_msg(machine.last_err)))
			}
			free_compiler(compiler);
			free_machine(&machine);
			free(instructions);
			free(compiler);
		}
		else
			PANIC(("Unexpected flag \"%s\".", flag));
	}
	
	exit(EXIT_SUCCESS);
}