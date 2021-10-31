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

int main(int argc, const char* argv[]) {
	int current_arg = 0;

	const char* working_dir = READ_ARG;
	
	char* source = file_read_source(READ_ARG);
	
	ast_parser_t parser;
	init_ast_parser(&parser, source);

	ast_t ast;

	int s = init_ast(&ast, &parser);

	machine_t machine;
	compiler_t compiler;
	int k = init_compiler(&compiler, &machine, &ast);

	free_ast_parser(&parser);
	free_ast(&ast);

	exit(EXIT_SUCCESS);
}