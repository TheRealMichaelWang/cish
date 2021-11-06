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
#define EXPECT_FLAG(FLAG) if(strcmp(READ_ARG, FLAG)) { ABORT(("Unexpected flag %s.", FLAG)); }

int main(int argc, char* argv[]) {
	int current_arg = 0;

	char* working_dir = READ_ARG;
	
	char* op_flag = READ_ARG;

	if (!strcmp(op_flag, "-cr")) {
		ast_parser_t parser;
		if (!init_ast_parser(&parser, READ_ARG))
			ABORT(("Error initializing parser(%s).", get_err_msg(parser.last_err)));
		ast_t ast;
		if (!init_ast(&ast, &parser)) {
			print_error_trace(parser.multi_scanner);
			ABORT(("Syntax error(%s).", get_err_msg(parser.last_err)));
		}
		free_ast_parser(&parser);

		machine_t machine;
		compiler_t compiler;
		if (!compile(&compiler, &machine, &ast))
			ABORT(("Compilation failiure(%s).", get_err_msg(compiler.last_err)));
		free_ast(&ast);

		install_stdlib(&machine, 100);
		if (!machine_execute(&machine, compiler.ins_builder.instructions, compiler.ins_builder.instruction_count))
			ABORT(("Runtime error(%s).", get_err_msg(machine.last_err)));
		free_machine(&machine);
		free(compiler.ins_builder.instructions);
	}
	else
		ABORT(("Unrecognized flag(%s).", op_flag));

	exit(EXIT_SUCCESS);
}