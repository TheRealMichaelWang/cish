#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "error.h"
#include "common.h"
#include "ast.h"

#define LAST_TOK ast_parser->multi_scanner.last_tok
#define MATCH_TOK(TYPE) if(LAST_TOK.type != TYPE) PANIC(ast_parser, ERROR_UNEXPECTED_TOK)
#define READ_TOK PANIC_ON_FAIL(multi_scanner_scan_tok(&ast_parser->multi_scanner), ast_parser, ast_parser->multi_scanner.last_err);

typedef struct ast_parser_frame ast_parser_frame_t;

typedef struct ast_parser_frame {
	ast_var_cache_entry_t* locals;
	typecheck_type_t* return_type;

	uint64_t* generics;

	uint16_t local_count, allocated_locals;
	uint8_t generic_count;

	ast_parser_frame_t* parent_frame;
} ast_parser_frame_t;

typedef struct ast_parser {
	ast_parser_frame_t frames[32];
	uint8_t current_frame;

	ast_var_cache_entry_t* globals;
	uint16_t global_count, allocated_globals, constant_count;

	multi_scanner_t multi_scanner;

	error_t last_err;
} ast_parser_t;

static const int op_precs[] = {
	2, 2, 2, 2, 2, 2,

	3, 3, 4, 4, 4, 5,

	1, 1
};

static const int parse_value(ast_parser_t* ast_parser, ast_value_t* value);
static const int expression(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t type, int min_prec);

static const int ast_code_block_append(ast_code_block_t* code_block, ast_statement_t statement) {
	if (code_block->instructions == code_block->allocated_instructions) {
		ast_statement_t* new_ins = realloc(code_block->instructions, ((int)code_block->allocated_instructions *= 2) * sizeof(ast_statement_t));
		ESCAPE_ON_FAIL(new_ins);
		code_block->instructions = new_ins;
	}
	code_block->instructions[code_block->instruction_count++] = statement;
}

static const int init_ast_parser(ast_parser_t* ast_parser, const char* source) {
	PANIC_ON_FAIL(ast_parser->globals = malloc((ast_parser->allocated_globals = 16) * sizeof(ast_var_cache_entry_t)), ast_parser, ERROR_MEMORY);
	ast_parser->global_count = 0;
	ast_parser->constant_count = 0;
	ast_parser->current_frame = 0;
	init_multi_scanner(&ast_parser->multi_scanner, source, strlen(source));
	return 1;
}

static const int free_ast_parser(ast_parser_t* ast_parser) {
	while (ast_parser->current_frame)
		ast_parser_close_frame(ast_parser);
	free(ast_parser->globals);
}

static const int ast_parser_new_frame(ast_parser_t* ast_parser, typecheck_type_t* return_type, int access_previous) {
	if (ast_parser->current_frame == 32)
		PANIC(ast_parser, ERROR_INTERNAL);
	ast_parser_frame_t* next_frame = &ast_parser->frames[ast_parser->current_frame++];
	PANIC_ON_FAIL(next_frame->locals = malloc((next_frame->allocated_locals = 8) * sizeof(ast_var_cache_entry_t)), ast_parser, ERROR_MEMORY);
	PANIC_ON_FAIL(next_frame->generics = malloc(100 * sizeof(uint64_t)), ast_parser, ERROR_MEMORY);
	next_frame->local_count = 0;
	next_frame->generic_count = 0;
	if (access_previous) {
		next_frame->parent_frame = &ast_parser->frames[ast_parser->current_frame - 2];
		next_frame->return_type = next_frame->parent_frame->return_type;
	}
	else {
		next_frame->return_type = return_type;
		next_frame->parent_frame = NULL;
	}
	return 1;
}

static const int ast_parser_close_frame(ast_parser_t* ast_parser) {
	PANIC_ON_FAIL(ast_parser->current_frame, ast_parser, ERROR_INTERNAL);
	ast_parser_frame_t* free_frame = &ast_parser->frames[--ast_parser->current_frame];
	free(free_frame->locals);
	free(free_frame->generics);
	return 1;
}

static ast_parser_frame_t* ast_parser_find_var(ast_parser_t* ast_parser, uint64_t id) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	while (current_frame) {
		for (uint_fast16_t i = 0; i < current_frame->local_count; i++)
			if (current_frame->locals[i].id_hash == id)
				return current_frame->locals[i].var_info;
		current_frame = current_frame->parent_frame;
	}
	for (uint_fast16_t i = 0; i < ast_parser->global_count; i++)
		if (ast_parser->globals[i].id_hash == id)
			return ast_parser->globals[i].var_info;
	return NULL;
}

static const int ast_parser_decl_var(ast_parser_t* ast_parser, uint64_t id, ast_var_info_t* var_info) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	if (ast_parser_find_var(ast_parser, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	if (var_info->is_global) {
		if (ast_parser->global_count) {
			ast_var_cache_entry_t* new_globals = realloc(ast_parser->globals, ((int)ast_parser->allocated_globals *= 2) * sizeof(ast_var_cache_entry_t));
			PANIC_ON_FAIL(new_globals, ast_parser, ERROR_MEMORY);
			ast_parser->globals = new_globals;
		}
		ast_parser->globals[(int)ast_parser->global_count++] = (ast_var_cache_entry_t){
			.id_hash = id,
			.var_info = var_info
		};
	}
	else {
		if (current_frame->local_count == current_frame->allocated_locals) {
			ast_var_cache_entry_t* new_locals = realloc(current_frame->locals, ((int)current_frame->allocated_locals *= 2) * sizeof(ast_var_cache_entry_t));
			PANIC_ON_FAIL(new_locals, ast_parser, ERROR_MEMORY);
			current_frame->locals = new_locals;
		}
		current_frame->locals[current_frame->local_count++] = (ast_var_cache_entry_t){
			.id_hash = id,
			.var_info = var_info
		};
	}
	return 1;
}

static uint8_t ast_parser_find_generic(ast_parser_t* ast_parser, uint64_t id) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	while (current_frame) {
		for (uint_fast8_t i = 0; i < current_frame->generic_count; i++)
			if (current_frame->generics[i] == id)
				return i + 1;
	}
	return 0;
}

static const int ast_parser_decl_generic(ast_parser_t* ast_parser, uint64_t id) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	if (ast_parser_find_generic(ast_parser, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	if (current_frame->generic_count == 100)
		PANIC(ast_parser, ERROR_MEMORY);
	current_frame->generics[current_frame->generic_count++] = id;
	return 1;
}

static const int parse_type(ast_parser_t* ast_parser, typecheck_type_t* type, int allow_auto, int allow_nothing) {
	if (LAST_TOK.type >= TOK_TYPECHECK_BOOL && LAST_TOK.type < TOK_TYPECHECK_PROC)
		type->type = TYPE_PRIMATIVE_BOOL + (LAST_TOK.type - TOK_TYPECHECK_BOOL);
	else if (LAST_TOK.type == TOK_AUTO || LAST_TOK.type == TOK_NOTHING)
		PANIC_ON_FAIL(LAST_TOK.type == TOK_AUTO ? allow_auto : allow_nothing, ast_parser, ERROR_TYPE_NOT_ALLOWED)
	else if (LAST_TOK.type == TOK_IDENTIFIER) {
		type->match = ast_parser_find_generic(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length));
		if (type->match)
			type->type = TYPE_TYPEARG;
		else
			PANIC(ast_parser, ERROR_UNDECLARED);
	}
	else
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	READ_TOK;
	if (LAST_TOK.type == TOK_LESS) {
		static typecheck_type_t sub_types[100];
		uint8_t found_sub_types = 0;
		do{
			READ_TOK;
			if (found_sub_types == TYPE_MAX_SUBTYPES)
				PANIC(ast_parser, ERROR_MEMORY);
			ast_parser_parse_type(ast_parser, &sub_types[found_sub_types++], 0, type->type == TOK_TYPECHECK_PROC && found_sub_types == 0);
		} while (LAST_TOK.type != TOK_COMMA);
		READ_TOK;
		MATCH_TOK(TOK_MORE);
		PANIC_ON_FAIL(type->sub_types = malloc(found_sub_types * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		memcpy(type->sub_types, sub_types, found_sub_types * sizeof(typecheck_type_t));
	}
	else if (type->type >= TYPE_SUPER_ARRAY)
		PANIC(ast_parser, ERROR_EXPECTED_SUB_TYPES)
	else
		type->sub_type_count = 0;
	return 1;
}

static const int parse_var_decl(ast_parser_t* ast_parser, ast_decl_var_t* ast_decl_var) {
	ast_decl_var->var_info.is_global = 0;
	ast_decl_var->var_info.is_readonly = 0;
	while (LAST_TOK.type == TOK_GLOBAL || LAST_TOK.type == TOK_READONLY) {
		if (LAST_TOK.type == TOK_GLOBAL)
			ast_decl_var->var_info.is_global = 1;
		else if (LAST_TOK.type == TOK_READONLY)
			ast_decl_var->var_info.is_readonly = 1;
		READ_TOK;
	}
	ESCAPE_ON_FAIL(parse_type(ast_parser, &ast_decl_var->var_info.type, 1, 0));
	MATCH_TOK(TOK_IDENTIFIER);
	uint64_t id = hash_s(LAST_TOK.str, LAST_TOK.length);
	READ_TOK;
	ESCAPE_ON_FAIL(ast_parser_decl_var(ast_parser, id, &ast_decl_var->var_info));
	MATCH_TOK(TOK_SET);
	READ_TOK;
	ESCAPE_ON_FAIL(parse_value(ast_parser, &ast_decl_var->set_value));
	return 1;
}

static const int parse_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, int encapsulated) {
	if (encapsulated) {
		MATCH_TOK(TOK_OPEN_BRACE);
		READ_TOK;
	}
	do {
		ast_statement_t statement;
		switch (LAST_TOK.type)
		{
		case TOK_READONLY:
		case TOK_GLOBAL:
		case TOK_TYPECHECK_ARRAY:
		case TOK_TYPECHECK_PROC:

		default:
			PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
		}
	}
}