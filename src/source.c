#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "compiler.h"
#include "machine.h"
#include "ast.h"
#include "file.h"
#include "stdlibf.h"
#include "debug.h"

#define ABORT(MSG) {printf MSG ; exit(EXIT_FAILURE);}

#define READ_ARG argv[current_arg++]
#define EXPECT_FLAG(FLAG) if(current_arg == argc || strcmp(READ_ARG, FLAG)) { ABORT(("Unexpected flag %s.\n", FLAG)); }

int main(int argc, char* argv[]) {
	int current_arg = 0;

	const char* working_dir = READ_ARG;
	
	if (current_arg == argc)
		ABORT(("Expected an operation flag/argument.\n"));
	const char* op_flag = READ_ARG;

	if (!strcmp(op_flag, "-cr") || !strcmp(op_flag, "-c") || !strcmp(op_flag, "-cd")) {
		ast_parser_t parser;
		EXPECT_FLAG("-s");
		if (!init_ast_parser(&parser, READ_ARG))
			ABORT(("Error initializing parser(%s).\n", get_err_msg(parser.last_err)));
		ast_t ast;
		if (!init_ast(&ast, &parser)) {
			print_error_trace(parser.multi_scanner);
			ABORT(("Syntax error(%s).\n", get_err_msg(parser.last_err)));
		}

		machine_t machine;
		compiler_t compiler;
		if (!compile(&compiler, &machine, &ast))
			ABORT(("Compilation failiure(%s).\n", get_err_msg(compiler.last_err)));

		machine_ins_t* machine_ins = malloc(compiler.ins_builder.instruction_count * sizeof(machine_ins_t));
		if(!machine_ins)
			ABORT(("Compilation failiure(memory).\n"));

		compiler_ins_to_machine_ins(compiler.ins_builder.instructions, machine_ins, compiler.ins_builder.instruction_count);
		free(compiler.ins_builder.instructions);

		free_ast_parser(&parser);
		free_ast(&ast);

		//print_instructions(machine_ins, compiler.ins_builder.instruction_count);

		if (!strcmp(op_flag, "-cr")) {
			install_stdlib(&machine);
			if (!machine_execute(&machine, machine_ins)) {
				printf("Last IP: %" PRIu64 "\n", machine.last_err_ip);
				ABORT(("Runtime error(%s).\n", get_err_msg(machine.last_err)));
			}
		}
		else if (!strcmp(op_flag, "-c")) {
			EXPECT_FLAG("-o");
			if (!file_save_compiled(READ_ARG, &ast, &machine, machine_ins, compiler.ins_builder.instruction_count))
				ABORT(("Error saving compiled binaries.\n"));
		}
		else
			print_instructions(machine_ins, compiler.ins_builder.instruction_count);
		free_machine(&machine);
		free(machine_ins);
	}
	else if (!strcmp(op_flag, "-r") || !strcmp(op_flag, "-rd")) {
		machine_t machine;
		uint16_t instruction_count;
		EXPECT_FLAG("-s");
		machine_ins_t* instructions = file_load_ins(READ_ARG, &machine, &instruction_count, NULL);
		if (!instructions)
			ABORT(("Unable to load binaries from file.\n"));
		if (!strcmp(op_flag, "-r")) {
			install_stdlib(&machine);
			if (!machine_execute(&machine, instructions)) {
				printf("Last IP: %" PRIu64 "\n", machine.last_err_ip);
				ABORT(("Runtime error(%s).\n", get_err_msg(machine.last_err)))
			}
		}
		else
			print_instructions(instructions, instruction_count);
		free_machine(&machine);
		free(instructions);
	}
	else if (!strcmp(op_flag, "-info")) {
		printf("SUPERFORTH\n"
				"Writen and developed by Michael Wang, 2020-2022.\n"
				"General Documentation: https://github.com/TheRealMichaelWang/superforth/wiki \n"
				"CLI Help: https://github.com/TheRealMichaelWang/superforth/wiki/Command-Line-Usage \n"
				"Targeted Build Platform: "
#ifdef _WIN32
			"WINDOWS"
#else
			"LINUX/UNIX"
#endif
				"\n");
	}
	else
		ABORT(("Unrecognized flag(%s).\n", op_flag));

	exit(EXIT_SUCCESS);
}