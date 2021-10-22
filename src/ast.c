#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "error.h"
#include "common.h"
#include "ast.h"

#define LAST_TOK ast_parser->multi_scanner.last_tok
#define MATCH_TOK(TYPE) if(LAST_TOK.type != TYPE) PANIC(ast_parser, ERROR_UNEXPECTED_TOK)
#define READ_TOK PANIC_ON_FAIL(multi_scanner_scan_tok(&ast_parser->multi_scanner), ast_parser, ast_parser->multi_scanner.last_err);

#define CURRENT_FRAME ast_parser->frames[ast_parser->current_frame - 1]

static const int parse_value(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type);
static const int parse_expression(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type, int min_prec);

static const int parse_type(ast_parser_t* ast_parser, typecheck_type_t* type, int allow_auto, int allow_nothing);
static const int parse_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, int encapsulated);

static const int ast_code_block_append(ast_code_block_t* code_block, ast_statement_t statement) {
	if (code_block->instructions == code_block->allocated_instructions) {
		ast_statement_t* new_ins = realloc(code_block->instructions, ((int)code_block->allocated_instructions *= 2) * sizeof(ast_statement_t));
		ESCAPE_ON_FAIL(new_ins);
		code_block->instructions = new_ins;
	}
	code_block->instructions[code_block->instruction_count++] = statement;
}

static const int ast_parser_new_frame(ast_parser_t* ast_parser, typecheck_type_t* return_type, int access_previous) {
	if (ast_parser->current_frame == 32)
		PANIC(ast_parser, ERROR_INTERNAL);
	ast_parser_frame_t* next_frame = &ast_parser->frames[ast_parser->current_frame++];
	PANIC_ON_FAIL(next_frame->locals = malloc((next_frame->allocated_locals = 8) * sizeof(ast_var_cache_entry_t)), ast_parser, ERROR_MEMORY);
	next_frame->local_count = 0;
	next_frame->generic_count = 0;
	next_frame->total_locals = 0;
	if (access_previous) {
		next_frame->parent_frame = &ast_parser->frames[ast_parser->current_frame - 2];
		next_frame->return_type = next_frame->parent_frame->return_type;
		next_frame->local_offset = next_frame->parent_frame->local_count + next_frame->parent_frame->local_offset;
	}
	else {
		PANIC_ON_FAIL(next_frame->generics = malloc(100 * sizeof(uint64_t)), ast_parser, ERROR_MEMORY);
		next_frame->return_type = return_type;
		next_frame->parent_frame = NULL;
		next_frame->local_offset = 0;
	}
	return 1;
}

static const int ast_parser_close_frame(ast_parser_t* ast_parser) {
	PANIC_ON_FAIL(ast_parser->current_frame, ast_parser, ERROR_INTERNAL);
	ast_parser_frame_t* free_frame = &ast_parser->frames[--ast_parser->current_frame];
	if(free_frame->local_offset + free_frame->local_count > free_frame->total_locals)
		free_frame->total_locals = free_frame->local_offset + free_frame->local_count;
	if (free_frame->parent_frame) {
		if (free_frame->total_locals > free_frame->parent_frame->total_locals)
			free_frame->parent_frame->total_locals = free_frame->total_locals;
	}
	else
		free(free_frame->generics);
	free(free_frame->locals);
	return 1;
}

static ast_var_info_t* ast_parser_find_var(ast_parser_t* ast_parser, uint64_t id) {
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
			ast_var_cache_entry_t* new_globals = realloc(ast_parser->globals, (ast_parser->allocated_globals *= 2) * sizeof(ast_var_cache_entry_t));
			PANIC_ON_FAIL(new_globals, ast_parser, ERROR_MEMORY);
			ast_parser->globals = new_globals;
		}
		var_info->id = ast_parser->global_count;
		ast_parser->globals[ast_parser->global_count++] = (ast_var_cache_entry_t){
			.id_hash = id,
			.var_info = var_info
		};
	}
	else {
		if (current_frame->local_count == current_frame->allocated_locals) {
			ast_var_cache_entry_t* new_locals = realloc(current_frame->locals, (current_frame->allocated_locals *= 2) * sizeof(ast_var_cache_entry_t));
			PANIC_ON_FAIL(new_locals, ast_parser, ERROR_MEMORY);
			current_frame->locals = new_locals;
		}
		var_info->id = current_frame->local_count + current_frame->local_offset;
		current_frame->locals[current_frame->local_count++] = (ast_var_cache_entry_t){
			.id_hash = id,
			.var_info = var_info
		};
	}
	return 1;
}

static uint8_t ast_parser_find_generic(ast_parser_t* ast_parser, uint64_t id) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	while (current_frame->parent_frame)
		current_frame = current_frame->parent_frame;
	for (uint_fast8_t i = 0; i < current_frame->generic_count; i++)
		if (current_frame->generics[i] == id)
			return i + 1;
	return 0;
}

static const int ast_parser_decl_generic(ast_parser_t* ast_parser, uint64_t id) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	if (ast_parser_find_generic(ast_parser, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	while (current_frame->parent_frame)
		current_frame = current_frame->parent_frame;
	if (current_frame->generic_count == 100)
		PANIC(ast_parser, ERROR_MEMORY);
	current_frame->generics[current_frame->generic_count++] = id;
	return 1;
}

const int init_ast_parser(ast_parser_t* ast_parser, const char* source) {
	PANIC_ON_FAIL(ast_parser->globals = malloc((ast_parser->allocated_globals = 16) * sizeof(ast_var_cache_entry_t)), ast_parser, ERROR_MEMORY);
	ast_parser->global_count = 0;
	ast_parser->constant_count = 0;
	ast_parser->current_frame = 0;
	init_multi_scanner(&ast_parser->multi_scanner, source, strlen(source));
	return 1;
}

void free_ast_parser(ast_parser_t* ast_parser) {
	while (ast_parser->current_frame)
		ast_parser_close_frame(ast_parser);
	free(ast_parser->globals);
}

static const int parse_subtypes(ast_parser_t* ast_parser, typecheck_type_t* super_type) {
	MATCH_TOK(TOK_LESS);
	static typecheck_type_t sub_types[TYPE_MAX_SUBTYPES];
	uint8_t found_sub_types = 0;
	do {
		READ_TOK;
		if (found_sub_types == TYPE_MAX_SUBTYPES)
			PANIC(ast_parser, ERROR_MEMORY);
		ESCAPE_ON_FAIL(parse_type(ast_parser, &sub_types[found_sub_types++], 0, super_type->type == TOK_TYPECHECK_PROC && found_sub_types == 0));
	} while (LAST_TOK.type == TOK_COMMA);
	READ_TOK;
	MATCH_TOK(TOK_MORE);
	PANIC_ON_FAIL(super_type->sub_types = malloc(found_sub_types * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
	memcpy(super_type->sub_types, sub_types, found_sub_types * sizeof(typecheck_type_t));
	return 1;
}

static const int parse_type(ast_parser_t* ast_parser, typecheck_type_t* type, int allow_auto, int allow_nothing) {
	if (LAST_TOK.type >= TOK_TYPECHECK_BOOL && LAST_TOK.type <= TOK_TYPECHECK_PROC)
		type->type = TYPE_PRIMATIVE_BOOL + (LAST_TOK.type - TOK_TYPECHECK_BOOL);
	else if (LAST_TOK.type == TOK_AUTO || LAST_TOK.type == TOK_NOTHING) {
		PANIC_ON_FAIL(LAST_TOK.type == TOK_AUTO ? allow_auto : allow_nothing, ast_parser, ERROR_TYPE_NOT_ALLOWED);
		type->type = LAST_TOK.type - TOK_AUTO + TYPE_AUTO;
	}
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
	if (type->type >= TYPE_SUPER_ARRAY) {
		ESCAPE_ON_FAIL(parse_subtypes(ast_parser, type));
		if (type->type == TYPE_SUPER_ARRAY && type->sub_type_count != 1)
			PANIC(ast_parser, ERROR_EXPECTED_SUB_TYPES);
	}
	return 1;
}

static const int parse_type_params(ast_parser_t* ast_parser) {
	MATCH_TOK(TOK_LESS);
	while (LAST_TOK.type != TOK_MORE) {
		READ_TOK;
		MATCH_TOK(TOK_IDENTIFIER);
		ESCAPE_ON_FAIL(ast_parser_decl_generic(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length)));
		if (LAST_TOK.type != TOK_COMMA)
			MATCH_TOK(TOK_MORE);
	}
	READ_TOK;
}

static const int parse_prim_value(ast_parser_t* ast_parser, ast_primative_t* primative) {
	switch (LAST_TOK.type)
	{
	case TOK_NUMERICAL:
		for (uint_fast32_t i = 0; i < LAST_TOK.length; i++) {
			if ((LAST_TOK.str[i] == 'f' && i == LAST_TOK.length - 1) || LAST_TOK.str[i] == '.') {
				primative->data.float_int = strtod(LAST_TOK.str, NULL);
				primative->type = AST_PRIMATIVE_FLOAT;
			}
			else if (LAST_TOK.str[i] == 'h' && i == LAST_TOK.length - 1) {
				primative->data.long_int = strtol(LAST_TOK.str, NULL, 16);
				primative->type = AST_PRIMATIVE_LONG;
			}
		}
		primative->data.long_int = strtol(LAST_TOK.str, NULL, 10);
		primative->type = AST_PRIMATIVE_LONG;
		break;
	case TOK_CHAR: {
		primative->type = AST_PRIMATIVE_CHAR;
		scanner_t scanner;
		init_scanner(&scanner, LAST_TOK.str, LAST_TOK.length, 0);
		PANIC_ON_FAIL(scanner_scan_char(&scanner), ast_parser, scanner.last_err);
		primative->data.character = scanner.last_char;
		break;
	}
	case TOK_TRUE:
	case TOK_FALSE:
		primative->data.bool_flag = LAST_TOK.type - TOK_FALSE;
		break;
	default:
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	};
	primative->id = ast_parser->constant_count++;
	READ_TOK;
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
	ESCAPE_ON_FAIL(parse_expression(ast_parser, &ast_decl_var->set_value, &ast_decl_var->var_info.type, 0));
	return 1;
}

static const int parse_condition(ast_parser_t* ast_parser, ast_cond_t* conditional) {
	MATCH_TOK(TOK_OPEN_PAREN);
	READ_TOK;
	ESCAPE_ON_FAIL(parse_expression(ast_parser, &conditional->condition, &typecheck_bool, 0));
	conditional->has_cond_val = 1;
	MATCH_TOK(TOK_CLOSE_PAREN);
	READ_TOK;
	return 1;
}

static const int parse_if_else(ast_parser_t* ast_parser, ast_cond_t* conditional) {
	MATCH_TOK(TOK_IF);
	READ_TOK;
	ESCAPE_ON_FAIL(parse_condition(ast_parser, conditional));
	ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 1));
	ESCAPE_ON_FAIL(parse_code_block(ast_parser, &conditional->exec_block, 1));
	ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
	if (LAST_TOK.type == TOK_ELSE) {
		READ_TOK;
		PANIC_ON_FAIL(conditional->next_if_false = malloc(sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);
		if (LAST_TOK.type == TOK_IF)
			ESCAPE_ON_FAIL(parse_if_else(ast_parser, conditional->next_if_false))
		else {
			conditional->next_if_false->has_cond_val = 0;
			conditional->next_if_false->next_if_false = NULL;
			ESCAPE_ON_FAIL(parse_code_block(ast_parser, &conditional->next_if_false->exec_block, 1));
		}
	}
	else
		conditional->next_if_false = NULL;
	return 1;
}

static const int parse_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, int encapsulated) {
	PANIC_ON_FAIL(code_block->instructions = malloc((code_block->allocated_instructions = 16) * sizeof(ast_statement_t)), ast_parser, ERROR_MEMORY);
	code_block->instruction_count = 0;
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
		case TOK_AUTO:
		case TOK_TYPECHECK_BOOL:
		case TOK_TYPECHECK_CHAR:
		case TOK_TYPECHECK_FLOAT:
		case TOK_TYPECHECK_LONG:
		case TOK_TYPECHECK_ARRAY:
		case TOK_TYPECHECK_PROC:
			statement.type = AST_STATEMENT_DECL_VAR;
			ESCAPE_ON_FAIL(parse_var_decl(ast_parser, &statement.data.var_decl));
			break;
		case TOK_IF:
			statement.type = AST_STATEMENT_COND;
			PANIC_ON_FAIL(statement.data.conditional = malloc(sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);
			ESCAPE_ON_FAIL(parse_if_else(ast_parser, statement.data.conditional));
			goto no_check_semicolon;
		case TOK_WHILE: {
			READ_TOK;
			statement.type = AST_STATEMENT_COND;
			PANIC_ON_FAIL(statement.data.conditional = malloc(sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);
			ESCAPE_ON_FAIL(parse_condition(ast_parser, statement.data.conditional));
			ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 1));
			ESCAPE_ON_FAIL(parse_code_block(ast_parser, &statement.data.conditional->exec_block, 1));
			ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
			statement.data.conditional->next_if_true = statement.data.conditional;
			statement.data.conditional->next_if_false = NULL;
			goto no_check_semicolon;
		}
		case TOK_IDENTIFIER: {
			statement.type = AST_STATEMENT_VALUE;
			typecheck_type_t type = { .type = TYPE_AUTO };
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &statement.data.value, &type, 0));
			break;
		}
		case TOK_CONTINUE:
		case TOK_BREAK:
			statement.type = AST_STATEMENT_CONTINUE + LAST_TOK.type - TOK_CONTINUE;
			break;
		case TOK_RETURN:
			READ_TOK;
			if (LAST_TOK.type == TOK_SEMICOLON)
				statement.type = AST_STATEMENT_RETURN;
			else {
				statement.type = AST_STATEMENT_RETURN_VALUE;
				PANIC_ON_FAIL(CURRENT_FRAME.return_type, ast_parser, ERROR_CANNOT_RETURN);
				ESCAPE_ON_FAIL(parse_expression(ast_parser, &statement.data.value, CURRENT_FRAME.return_type, 0));
			}
			break;
		default:
			PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
		}
		
		MATCH_TOK(TOK_SEMICOLON);
		READ_TOK;
		no_check_semicolon:
			PANIC_ON_FAIL(ast_code_block_append(code_block, statement), ast_parser, ERROR_MEMORY);
	} while (encapsulated ? LAST_TOK.type != TOK_CLOSE_BRACE : LAST_TOK.type != TOK_EOF);
	READ_TOK;
	return 1;
}

static const int parse_value(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type) {
	switch (LAST_TOK.type) {
	case TOK_NUMERICAL:
	case TOK_CHAR:
	case TOK_TRUE:
	case TOK_FALSE:
		ESCAPE_ON_FAIL(parse_prim_value(ast_parser, &value->data.primative));
		value->value_type = AST_VALUE_PRIMATIVE;
		value->type.type = TYPE_PRIMATIVE_BOOL + value->data.primative.type - AST_PRIMATIVE_BOOL;
		break;
	case TOK_STRING: {
		char* buffer = malloc(LAST_TOK.length);
		PANIC_ON_FAIL(buffer, ast_parser, ERROR_MEMORY);
		value->data.array_literal.element_count = 0;
		scanner_t str_scanner;
		init_scanner(&str_scanner, LAST_TOK.str, LAST_TOK.length, 0);
		scanner_scan_char(&str_scanner);
		while (str_scanner.last_char) {
			buffer[value->data.array_literal.element_count++] = str_scanner.last_char;
			scanner_scan_char(&str_scanner);
		}
		value->value_type = AST_VALUE_ARRAY_LITERAL;
		value->type.type = TYPE_SUPER_ARRAY;
		PANIC_ON_FAIL(value->type.sub_types = malloc(sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		value->type.sub_types->type = TYPE_PRIMATIVE_CHAR;
		value->type.sub_type_count = 1;
		value->data.array_literal.elem_type = value->type.sub_types;
		PANIC_ON_FAIL(value->data.array_literal.elements = malloc(value->data.array_literal.element_count * sizeof(ast_value_t)), ast_parser, ERROR_MEMORY)
			for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++) {
				value->data.array_literal.elements[i].data.primative = (ast_primative_t){
					.data.character = buffer[i],
					.id = ast_parser->constant_count++,
					.type = AST_PRIMATIVE_CHAR
				};
				value->data.array_literal.elements[i].value_type = AST_VALUE_PRIMATIVE;
				value->data.array_literal.elements[i].type.type = TYPE_PRIMATIVE_CHAR;
			}
		free(buffer);
		READ_TOK;
		break;
	}
	case TOK_OPEN_BRACKET: {
		value->value_type = AST_VALUE_ARRAY_LITERAL;
		value->type.type = TYPE_SUPER_ARRAY;
		PANIC_ON_FAIL(value->type.sub_types = malloc(sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		value->type.type = TYPE_AUTO;
		value->data.array_literal.elem_type = value->type.sub_types;

		uint32_t alloc_elems = 8;
		value->data.array_literal.element_count = 0;
		PANIC_ON_FAIL(value->data.array_literal.elements = malloc(alloc_elems * sizeof(ast_value_t)), ast_parser, ERROR_MEMORY);

		READ_TOK;
		while (LAST_TOK.type != TOK_CLOSE_BRACKET) {
			if (value->data.array_literal.element_count == alloc_elems) {
				ast_value_t* new_elems = realloc(value->data.array_literal.element_count, (alloc_elems *= 2) * sizeof(ast_value_t));
				PANIC_ON_FAIL(new_elems, ast_parser, ERROR_MEMORY);
				value->data.array_literal.elements = new_elems;
			}
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.array_literal.elements[value->data.array_literal.element_count++], value->type.sub_types, 0));
			if (LAST_TOK.type != TOK_CLOSE_BRACKET) {
				MATCH_TOK(TOK_COMMA);
				READ_TOK;
			}
		}
		READ_TOK;
		break;
	}
	case TOK_NEW:
		value->value_type = AST_VALUE_ALLOC_ARRAY;
		value->type.type = TYPE_SUPER_ARRAY;
		PANIC_ON_FAIL(value->type.sub_types = malloc(sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		PANIC_ON_FAIL(value->data.alloc_array = malloc(sizeof(ast_alloc_t)), ast_parser, ERROR_MEMORY);
		value->data.alloc_array->elem_type = value->type.sub_types;

		READ_TOK;
		ESCAPE_ON_FAIL(parse_type(ast_parser, value->data.alloc_array->elem_type, 0, 0));
		READ_TOK;
		MATCH_TOK(TOK_OPEN_BRACKET);
		READ_TOK;
		ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.alloc_array->size, &typecheck_int, 0));
		MATCH_TOK(TOK_CLOSE_BRACKET);
		READ_TOK;
		break;
	case TOK_IDENTIFIER: {
		ast_var_info_t* var_info = ast_parser_find_var(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length));
		PANIC_ON_FAIL(var_info, ast_parser, ERROR_UNDECLARED);
		PANIC_ON_FAIL(copy_typecheck_type(&value->type, var_info->type), ast_parser, ERROR_MEMORY);

		READ_TOK;
		if (LAST_TOK.type == TOK_SET) {
			READ_TOK;
			if (var_info->is_readonly)
				PANIC(ast_parser, ERROR_READONLY);
			value->value_type = AST_VALUE_SET_VAR;
			PANIC_ON_FAIL(value->data.set_var = malloc(sizeof(ast_set_var_t)), ast_parser, ERROR_UNDECLARED);
			value->data.set_var->var_info = var_info;
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.set_var->set_value, &var_info->type, 0));
		}
		else {
			value->value_type = AST_VALUE_VAR;
			value->data.variable = var_info;
		}
		break;
	}
	case TOK_OPEN_PAREN:
		READ_TOK;
		ESCAPE_ON_FAIL(parse_expression(ast_parser, value, type, 0));
		MATCH_TOK(TOK_CLOSE_PAREN);
		READ_TOK;
		break;
	case TOK_NOT:
	case TOK_HASHTAG:
	case TOK_SUBTRACT: {
		value->value_type = AST_VALUE_UNARY_OP;
		PANIC_ON_FAIL(value->data.unary_op = malloc(sizeof(ast_unary_op_t)), ast_parser, ERROR_MEMORY);
		value->data.unary_op->operator = LAST_TOK.type;
		if ((LAST_TOK.type == TOK_SUBTRACT && !typecheck_compatible(type, typecheck_int) && !typecheck_compatible(type, typecheck_float)) ||
			(LAST_TOK.type == TOK_HASHTAG && !typecheck_compatible(type, typecheck_array) ||
			(LAST_TOK.type == TOK_NOT && !typecheck_compatible(type, typecheck_bool))))
			PANIC(ast_parser, ERROR_UNEXPECTED_TYPE);
		READ_TOK;
		ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.unary_op->operand, LAST_TOK.type == TOK_SUBTRACT || LAST_TOK.type == TOK_NOT ? type : &typecheck_array, 0));
		break; 
	}
	case TOK_TYPECHECK_PROC: {
		READ_TOK;
		value->value_type = AST_VALUE_PROC;
		ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 0));
		if(LAST_TOK.type == TOK_LESS)
			ESCAPE_ON_FAIL(parse_type_params(ast_parser));
		PANIC_ON_FAIL(value->data.procedure = malloc(sizeof(ast_proc_t)), ast_parser, ERROR_MEMORY);
		value->data.procedure->param_count = 0;
		MATCH_TOK(TOK_OPEN_PAREN);
		while (LAST_TOK.type != TOK_CLOSE_PAREN)
		{
			if (value->data.procedure->param_count == TYPE_MAX_SUBTYPES - 1)
				PANIC(ast_parser, ERROR_INTERNAL);
			READ_TOK;
			value->data.procedure->params[value->data.procedure->param_count] = (ast_var_info_t){
				.is_global = 0,
				.is_readonly = 1
			};
			ESCAPE_ON_FAIL(parse_type(ast_parser, &value->data.procedure->params[value->data.procedure->param_count].type, 0, 0));
			MATCH_TOK(TOK_IDENTIFIER);
			ESCAPE_ON_FAIL(ast_parser_decl_var(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length), &value->data.procedure->params[value->data.procedure->param_count]));
			value->data.procedure->param_count++;
			READ_TOK;
			if (LAST_TOK.type != TOK_COMMA)
				MATCH_TOK(TOK_CLOSE_PAREN);
		}
		value->type.type = TYPE_SUPER_PROC;
		value->type.sub_types = malloc((value->type.sub_type_count = value->data.procedure->param_count + 1) * sizeof(typecheck_type_t));
		for (uint_fast8_t i = 0; i < value->data.procedure->param_count; i++)
			PANIC_ON_FAIL(copy_typecheck_type(&value->type.sub_types[i + 1], value->data.procedure->params[i].type), ast_parser, ERROR_MEMORY);
		READ_TOK;
		MATCH_TOK(TOK_RETURN);
		READ_TOK;
		ESCAPE_ON_FAIL(parse_type(ast_parser, &value->type.sub_types[0], 1, 0));
		CURRENT_FRAME.return_type = value->data.procedure->return_type = &value->type.sub_types[0];
		ast_var_info_t this_proc_var_info = {
			.is_global = 0,
			.is_readonly = 1,
			.type = value->type
		};
		ESCAPE_ON_FAIL(ast_parser_decl_var(ast_parser, 7572967076558961, &this_proc_var_info));
		ESCAPE_ON_FAIL(parse_code_block(ast_parser, &value->data.procedure->exec_block, 1));
		ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
		value->data.procedure->total_locals = ast_parser->frames[ast_parser->current_frame].total_locals;
		break;
	}
	default:
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	}
	while (LAST_TOK.type == TOK_OPEN_BRACKET || LAST_TOK.type == TOK_OPEN_PAREN) {
		if (LAST_TOK.type == TOK_OPEN_BRACKET) {
			READ_TOK;
			PANIC_ON_FAIL(value->type.type == TYPE_SUPER_ARRAY, ast_parser, ERROR_UNEXPECTED_TYPE);
			ast_value_t array_val, index_val;
			array_val = *value;
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &index_val, &typecheck_int, 0));
			MATCH_TOK(TOK_CLOSE_BRACKET);
			READ_TOK;
			if (LAST_TOK.type == TOK_SET) {
				value->value_type = AST_VALUE_SET_INDEX;
				PANIC_ON_FAIL(value->data.set_index = malloc(sizeof(ast_set_index_t)), ast_parser, ERROR_MEMORY);
				READ_TOK;
				value->data.set_index->array = array_val;
				value->data.set_index->index = index_val;
				ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.set_index->value, &array_val.type.sub_types[0], 0));
			}
			else {
				value->value_type = AST_VALUE_GET_INDEX;
				PANIC_ON_FAIL(value->data.get_index = malloc(sizeof(ast_get_index_t)), ast_parser, ERROR_MEMORY);
				value->data.get_index->array = array_val;
				value->data.get_index->index = index_val;
			}
			PANIC_ON_FAIL(copy_typecheck_type(&value->type, array_val.type.sub_types[0]), ast_parser, ERROR_MEMORY);
		}
		else {
			PANIC_ON_FAIL(value->type.type == TYPE_SUPER_PROC, ast_parser, ERROR_UNEXPECTED_TYPE);
			ast_value_t proc_val = *value;
			value->value_type = AST_VALUE_PROC_CALL;

			typecheck_type_t call_type;
			PANIC_ON_FAIL(copy_typecheck_type(&call_type, proc_val.type), ast_parser, ERROR_MEMORY);
			if (typecheck_has_type(call_type, TYPE_TYPEARG)) {
				typecheck_type_t typeargs;
				typeargs.type = TYPE_SUPER_PROC;
				ESCAPE_ON_FAIL(parse_subtypes(ast_parser, &typeargs));
				type_args_substitute(&typeargs, &call_type);
			}

			PANIC_ON_FAIL(value->data.proc_call = malloc(sizeof(ast_call_proc_t)), ast_parser, ERROR_MEMORY);
			value->data.proc_call->procedure = proc_val;
			value->data.proc_call->argument_count = 0;
			PANIC_ON_FAIL(copy_typecheck_type(&value->type, call_type.sub_types[0]), ast_parser, ERROR_MEMORY);

			while (LAST_TOK.type != TOK_CLOSE_PAREN) {
				READ_TOK;
				if (value->data.proc_call->argument_count == TYPE_MAX_SUBTYPES || value->data.proc_call->argument_count == call_type.sub_type_count)
					PANIC(ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);
				ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.proc_call->arguments[value->data.proc_call->argument_count], &call_type.sub_types[value->data.proc_call->argument_count + 1], 0));
				value->data.proc_call->argument_count++;
				if (LAST_TOK.type != TOK_COMMA)
					MATCH_TOK(TOK_CLOSE_PAREN);
			}
			free_typecheck_type(&call_type);
			READ_TOK;
		}
	}
	PANIC_ON_FAIL(typecheck_compatible(type, value->type), ast_parser, ERROR_UNEXPECTED_TYPE);
}

static const int parse_expression(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type, int min_prec) {
	static const int op_precs[] = {
		2, 2, 2, 2, 2, 2,
		3, 3, 4, 4, 4, 5,
		1, 1
	};
	ast_value_t lhs;
	lhs.type = (typecheck_type_t){ .type = TYPE_AUTO };
	ESCAPE_ON_FAIL(parse_value(ast_parser, &lhs, &lhs.type));
	while (LAST_TOK.type >= TOK_EQUALS && LAST_TOK.type <= TOK_OR && op_precs[LAST_TOK.type - TOK_EQUALS] > min_prec) {
		PANIC_ON_FAIL(value->data.binary_op = malloc(sizeof(ast_binary_op_t)), ast_parser, ERROR_MEMORY);
		value->data.binary_op->lhs = lhs;
		value->data.binary_op->operator = LAST_TOK.type;
		value->value_type = AST_VALUE_BINARY_OP;
		PANIC_ON_FAIL(copy_typecheck_type(&value->type, *type), ast_parser, ERROR_MEMORY);

		if (value->data.binary_op->operator >= TOK_EQUALS && value->data.binary_op->operator <= TOK_LESS_EQUAL)
			PANIC_ON_FAIL(typecheck_compatible(type, typecheck_bool), ast_parser, ERROR_UNEXPECTED_TYPE)
		else if(value->data.binary_op->operator >= TOK_ADD && value->data.binary_op->operator <= TOK_POWER)
			PANIC_ON_FAIL(typecheck_compatible(type, typecheck_int) || typecheck_compatible(type, typecheck_float), ast_parser, ERROR_UNEXPECTED_TYPE);
		if (value->data.binary_op->operator >= TOK_MORE && value->data.binary_op->operator <= TOK_POWER)
			PANIC_ON_FAIL(typecheck_compatible(&lhs.type, typecheck_int) || typecheck_compatible(&lhs.type, typecheck_float), ast_parser, ERROR_UNEXPECTED_TYPE)
		else if (value->data.binary_op->operator == TOK_AND || value->data.binary_op->operator == TOK_OR) {
			PANIC_ON_FAIL(typecheck_compatible(type, typecheck_bool), ast_parser, ERROR_UNEXPECTED_TYPE);
			PANIC_ON_FAIL(typecheck_compatible(&lhs.type, typecheck_bool), ast_parser, ERROR_UNEXPECTED_TYPE);
		}
		READ_TOK;
		ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.binary_op->rhs, &lhs.type, op_precs[value->data.binary_op->operator -TOK_EQUALS]));
		lhs = *value;
	}
	PANIC_ON_FAIL(typecheck_compatible(type, lhs.type), ast_parser, ERROR_UNEXPECTED_TYPE);
	*value = lhs;
	return 1;
}

const int init_ast(ast_t* ast, ast_parser_t* ast_parser) {
	ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 0));
	ESCAPE_ON_FAIL(parse_code_block(ast_parser, &ast->exec_block, 0));
	ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
	ast->constants = ast_parser->constant_count;
	ast->global_variables = ast_parser->global_count;
	return 1;
}

static void free_ast_code_block(ast_code_block_t* code_block);

static void free_ast_var_info(ast_var_info_t* var_info) {
	free_typecheck_type(&var_info->type);
}

static void free_ast_value(ast_value_t* value) {
	free_typecheck_type(&value->type);
	switch (value->value_type) {
	case AST_VALUE_ALLOC_ARRAY:
		free_ast_value(&value->data.alloc_array->size);
		free(value->data.alloc_array);
		break;
	case AST_VALUE_ARRAY_LITERAL:
		for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++)
			free_ast_value(&value->data.array_literal.elements[i]);
		free(value->data.array_literal.elements);
		break;
	case AST_VALUE_PROC:
		for (uint_fast8_t i = 0; i < value->data.procedure->param_count; i++)
			free_ast_var_info(&value->data.procedure->params[i]);
		free_ast_code_block(&value->data.procedure->exec_block);
		free(value->data.procedure);
		break;
	case AST_VALUE_SET_VAR:
		free_ast_value(&value->data.set_var->set_value);
		free(value->data.set_var);
	case AST_VALUE_SET_INDEX:
		free_ast_value(&value->data.set_index->array);
		free_ast_value(&value->data.set_index->index);
		free_ast_value(&value->data.set_index->value);
		free(value->data.set_index);
		break;
	case AST_VALUE_GET_INDEX:
		free_ast_value(&value->data.get_index->array);
		free_ast_value(&value->data.get_index->index);
		free(value->data.get_index);
		break;
	case AST_VALUE_BINARY_OP:
		free_ast_value(&value->data.binary_op->lhs);
		free_ast_value(&value->data.binary_op->rhs);
		free(value->data.binary_op);
		break;
	case AST_VALUE_UNARY_OP:
		free_ast_value(&value->data.unary_op->operand);
		free(value->data.unary_op);
		break;
	case AST_VALUE_PROC_CALL:
		free_ast_value(&value->data.proc_call->procedure);
		for (uint_fast8_t i = 0; i < value->data.proc_call->argument_count; i++)
			free_ast_value(&value->data.proc_call->arguments[i]);
		free(value->data.proc_call);
		break;
	}
}

static void free_ast_cond(ast_cond_t* conditional) {
	if (conditional->has_cond_val)
		free_ast_value(&conditional->condition);
	free_ast_code_block(&conditional->exec_block);
	if (conditional->next_if_false)
		free_ast_cond(conditional->next_if_false);
	free(conditional);
}

static void free_ast_code_block(ast_code_block_t* code_block) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++)
		switch (code_block->instructions[i].type) {
		case AST_STATEMENT_DECL_VAR:
			free_ast_var_info(&code_block->instructions[i].data.var_decl.var_info);
			free_ast_value(&code_block->instructions[i].data.var_decl.set_value);
			break;
		case AST_STATEMENT_COND:
			free_ast_cond(code_block->instructions[i].data.conditional);
			break;
		case AST_STATEMENT_RETURN_VALUE:
		case AST_STATEMENT_VALUE:
			free_ast_value(&code_block->instructions[i].data.value);
			break;
		case AST_STATEMENT_FOREIGN:
			free_ast_value(&code_block->instructions[i].data.foreign.id);
			if (code_block->instructions[i].data.foreign.has_input)
				free_ast_value(&code_block->instructions[i].data.foreign.input);
			break; 
		}
	free(code_block->instructions);
}

void free_ast(ast_t* ast) {
	free_ast_code_block(&ast->exec_block);
}