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
#include "error.h"

#define ABORT(MSG) {printf MSG ; exit(EXIT_FAILURE);}

#define READ_ARG argv[current_arg++]
#define EXPECT_FLAG(FLAG) if(current_arg == argc || strcmp(READ_ARG, FLAG)) { ABORT(("Unexpected flag, expected: %s\n", FLAG)); }

int main(int argc, char* argv[]) {
	int current_arg = 0;

	const char* working_dir = READ_ARG;
	
	if (current_arg == argc)
		ABORT(("Expected an operation flag/argument.\n"));
	const char* op_flag = READ_ARG;

	if (!strcmp(op_flag, "-cr") || !strcmp(op_flag, "-c") || !strcmp(op_flag, "-cd")) {
		safe_gc_t safe_gc;
		dbg_table_t dbg_table;
		if (!init_safe_gc(&safe_gc) || !init_debug_table(&dbg_table, &safe_gc))
			ABORT(("Error initializing safe-gc or debug table."));

		ast_parser_t parser;
		EXPECT_FLAG("-s");
		if (!init_ast_parser(&parser, &safe_gc, READ_ARG)) {
			free_safe_gc(&safe_gc, 1);
			ABORT(("Error initializing parser(%s).\n", get_err_msg(parser.last_err)));
		}

		ast_t ast;
		if (!init_ast(&ast, &parser, &dbg_table)) {
			print_error_trace(parser.multi_scanner);
			free_safe_gc(&safe_gc, 1);
			ABORT(("Syntax error(%s).\n", get_err_msg(parser.last_err)));
		}

		machine_t machine;
		compiler_t compiler;
		if (!compile(&compiler, &safe_gc, &machine, &ast)) {
			free_safe_gc(&safe_gc, 1);
			ABORT(("Compilation failiure(%s).\n", get_err_msg(compiler.last_err)));
		}

		machine_ins_t* machine_ins = safe_transfer_malloc(&safe_gc, compiler.ins_builder.instruction_count * sizeof(machine_ins_t));
		if (!machine_ins) {
			free_safe_gc(&safe_gc, 1);
			ABORT(("Compilation failiure(memory).\n"));
		}

		compiler_ins_to_machine_ins(compiler.ins_builder.instructions, machine_ins, compiler.ins_builder.instruction_count);
		free_safe_gc(&safe_gc, 0);

		if (!strcmp(op_flag, "-cr")) {
			if (!install_stdlib(&machine))
				ABORT(("Failed to install Cish standard native libraries.\n"));
			if (!machine_execute(&machine, machine_ins, machine_ins, 1)) {
				print_back_trace(&machine, &dbg_table, machine_ins);
				printf("Last IP: %" PRIu64 "\n", machine.last_err_ip);
				free_debug_table(&dbg_table);
				free(machine_ins);
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

		free_debug_table(&dbg_table);
		free_machine(&machine);
		free(machine_ins);
	}
	else if (!strcmp(op_flag, "-r") || !strcmp(op_flag, "-rd")) {
		machine_t machine;
		uint16_t instruction_count;
		EXPECT_FLAG("-s");
		safe_gc_t safe_gc;
		if (!init_safe_gc(&safe_gc))
			ABORT(("Unable to initialize safe gc."));
		machine_ins_t* instructions = file_load_ins(READ_ARG, &safe_gc, &machine, &instruction_count, NULL, NULL);
		if (!instructions) {
			free_safe_gc(&safe_gc, 1);
			ABORT(("Unable to load binaries from file.\n"));
		}
		free_safe_gc(&safe_gc, 0);
		if (!strcmp(op_flag, "-r")) {
			if (!install_stdlib(&machine))
				ABORT(("Failed to install Cish standard native libraries.\n"));
			if (!machine_execute(&machine, instructions, instructions, 1)) {
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
		printf("CISH\n"
				"Writen and developed by Michael Wang, 2020-2022.\n"
				"General Documentation: https://github.com/TheRealMichaelWang/cish/wiki \n"
				"CLI Help: https://github.com/TheRealMichaelWang/cish/wiki/Command-Line-Usage \n"
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