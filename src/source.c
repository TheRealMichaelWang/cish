#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "compiler.h"
#include "machine.h"
#include "ast.h"
#include "file.h"
#include "stdlib.h"
#include "debug.h"

#define ABORT(MSG) {printf MSG ; exit(EXIT_FAILURE);}

#define READ_ARG argv[current_arg++]
#define EXPECT_FLAG(FLAG) if(current_arg == argc || strcmp(READ_ARG, FLAG)) { ABORT(("Unexpected flag %s.", FLAG)); }

int main(int argc, char* argv[]) {
	int current_arg = 0;

	const char* working_dir = READ_ARG;
	
	if (current_arg == argc)
		ABORT(("Expected an operation flag/argument."));
	const char* op_flag = READ_ARG;

	if (!strcmp(op_flag, "-cr") || !strcmp(op_flag, "-c") || !strcmp(op_flag, "-cd")) {
		ast_parser_t parser;
		EXPECT_FLAG("-s");
		if (!init_ast_parser(&parser, READ_ARG))
			ABORT(("Error initializing parser(%s).", get_err_msg(parser.last_err)));
		ast_t ast;
		if (!init_ast(&ast, &parser)) {
			print_error_trace(parser.multi_scanner);
			ABORT(("Syntax error(%s).", get_err_msg(parser.last_err)));
		}

		machine_t machine;
		compiler_t compiler;
		if (!compile(&compiler, &machine, &ast))
			ABORT(("Compilation failiure(%s).", get_err_msg(compiler.last_err)));
		free_ast_parser(&parser);
		free_ast(&ast);

		//print_instructions(compiler.ins_builder.instructions, compiler.ins_builder.instruction_count);

		if (!strcmp(op_flag, "-cr")) {
			install_stdlib(&machine);
			if (!machine_execute(&machine, compiler.ins_builder.instructions))
				ABORT(("Runtime error(%s).", get_err_msg(machine.last_err)));
		}
		else if (!strcmp(op_flag, "-c")) {
			EXPECT_FLAG("-o");
			if (!file_save_compiled(READ_ARG, &parser, &machine, compiler.ins_builder.instructions, compiler.ins_builder.instruction_count))
				ABORT(("Error saving compiled binaries."));
		}
		else
			print_instructions(compiler.ins_builder.instructions, compiler.ins_builder.instruction_count);
		free_machine(&machine);
		free(compiler.ins_builder.instructions);
	}
	else if (!strcmp(op_flag, "-r") || !strcmp(op_flag, "-rd")) {
		machine_t machine;
		uint16_t instruction_count;
		EXPECT_FLAG("-s");
		machine_ins_t* instructions = file_load_ins(READ_ARG, &machine, &instruction_count);
		if (!instructions)
			ABORT(("Unable to load binaries from file."));
		if (!strcmp(op_flag, "-r")) {
			install_stdlib(&machine);
			if (!machine_execute(&machine, instructions))
				ABORT(("Runtime error(%s).", get_err_msg(machine.last_err)))
		}
		else
			print_instructions(instructions, instruction_count);
		free_machine(&machine);
		free(instructions);
	}
	else if (!strcmp(op_flag, "-info")) {
		printf("SUPERFORTH\n"
				"Writen and developed by Michael Wang, 2020-2021.");
	}
	else
		ABORT(("Unrecognized flag(%s).", op_flag));

	exit(EXIT_SUCCESS);
}