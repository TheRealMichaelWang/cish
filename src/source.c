#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "common.h"
#include "ast.h"
#include "compiler.h"
#include "machine.h"
#include "debug.h"
#include "labels.h"
#include "emit.h"

#define ABORT(MSG) {printf MSG ; putchar('\n'); exit(EXIT_FAILURE);}

#define READ_ARG argv[current_arg++]
#define EXPECT_FLAG(FLAG) if(current_arg == argc || strcmp(READ_ARG, FLAG)) { ABORT(("Unexpected flag %s.\n", FLAG)); }

#define HAS_EXT_FLAG(FLAG) has_flag(FLAG, argv, extra_flags, argc)

int has_flag(const char* flag, const char** argv, int extra_flag_start, int argc) {
	for (int i = extra_flag_start; i < argc; i++)
		if (!strcmp(argv[i], flag))
			return 1;
	return 0;
}

int main(int argc, const char** argv) {
	int current_arg = 0;
	const char* working_dir = READ_ARG;

	puts("Capote SuperForth GCC/Pros Transpiler\n" 
			"Written by Michael Wang 2022\n\n"
			
			"This is an experimental program, and may not support the latest SuperForth features. Expect any version signifigantly above or below SuperForth v1.0 to not compile.\n"
			"This program was created exclusivley for Husky Robotics. Do not distribute.\n");

	EXPECT_FLAG("-s");
	const char* source = READ_ARG;
	if (strcmp(get_filepath_ext(source), "txt") && strcmp(get_filepath_ext(source), "sf"))
		ABORT(("Unexpected source file extension %s. Expect a SuperForth source(.txt or .sf).", get_filepath_ext(source)));
	
	safe_gc_t safe_gc;
	if (!init_safe_gc(&safe_gc))
		ABORT(("Error initializing safe-gc."));

	ast_parser_t parser;
	if (!init_ast_parser(&parser, &safe_gc, source)) {
		free_safe_gc(&safe_gc, 1);
		ABORT(("Error initializing ast-parser. Cannot open file?"));
	}

	ast_t ast;
	if (!init_ast(&ast, &parser)) {
		print_error_trace(parser.multi_scanner);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Syntax error(%s).\n", get_err_msg(parser.last_err)));
	}

	compiler_t compiler;
	machine_t machine;
	if (!compile(&compiler, &safe_gc, &machine, &ast)) {
		free_safe_gc(&safe_gc, 1);
		ABORT(("IL Compilation failiure(%s).\n", get_err_msg(compiler.last_err)));
	}

	EXPECT_FLAG("-o");
	const char* output_path = READ_ARG;
	if (!strcmp(get_filepath_ext(output_path), "txt") || !strcmp(get_filepath_ext(output_path), "sf")) {
		free_machine(&machine);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Stopped compilation: Potentially unwanted source file override.\n"
			"Are you sure you want to override %s?", output_path));
	}

	int extra_flags = current_arg;

	FILE* output_file = fopen(output_path, "wb");
	if (!output_file) {
		free_machine(&machine);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Could not open output file: %s.", output_path));
	}

	int robo_mode = HAS_EXT_FLAG("-vex") || HAS_EXT_FLAG("-robo");
	if (!emit_c_header(output_file, robo_mode)) {
		free_machine(&machine);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Could not find stdheader.c. Please ensure it is in the compilers working directory."))
	}
	emit_constants(output_file, &ast, &machine);
	if (!emit_init(output_file, &ast, &machine)) {
		free_machine(&machine);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Could not emit initialization routines."));
	}

	label_buf_t label_buf;
	if (!init_label_buf(&label_buf, &safe_gc, compiler.ins_builder.instructions, compiler.ins_builder.instruction_count)) {
		free_machine(&machine);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Failed to initialze label buffer."));
	}

	if (!emit_instructions(output_file, &label_buf, compiler.ins_builder.instructions, compiler.ins_builder.instruction_count, HAS_EXT_FLAG("-dbg"))) {
		free_machine(&machine);
		free_safe_gc(&safe_gc, 1);
		ABORT(("Failed to emit instructions. Potentially unrecognized opcode."));
	}
	emit_final(output_file, robo_mode, source);

	free_machine(&machine);
	free_safe_gc(&safe_gc, 1);
	fclose(output_file);

	puts("Finished compilation succesfully.");
	if (robo_mode) {
		printf("Copy and paste %s into the src directory of your pros project. ", output_path);
		if (strcmp(output_path, "main.c"))
			puts("Ensure main.c and main.cpp are removed from the src directory.");
	}

	return 0;
}