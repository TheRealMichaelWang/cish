#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "error.h"
#include "file.h"
#include "ast.h"

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif // !max

#define READ_TOK PANIC_ON_NULL(scanner_scan_tok(&ast->include_stack.scanners[ast->include_stack.current_scanner]), ast, ast->include_stack.scanners[ast->include_stack.current_scanner].last_err)
#define LAST_TOK ast->include_stack.scanners[ast->include_stack.current_scanner].last_tok
#define MATCH_TOK(TOK) if(LAST_TOK.type != TOK) PANIC(ast, ERROR_UNEXPECTED_TOK);

static const int op_precs[] = {
	2, 2, 2, 2, 2, 2,

	3, 3, 4, 4, 4, 5,

	1, 1
};

static const int parse_value(ast_t* ast, ast_value_t* value);
static const int parse_expression(ast_t* ast, ast_value_t* value, int min_prec);
static const int parse_code_block(ast_t * ast, ast_code_block_t * code_block, uint16_t * current_reg, uint16_t * register_limit, int encapsulated, int top_level);

static void free_ast_value(ast_value_t * value);
static void free_ast_code_block(ast_code_block_t * code_block);

static void ast_var_cache_new_frame(ast_t* ast, typecheck_type_t* return_type, int access_previous_frame) {
	uint8_t stack_top = ++ast->var_cache.stack_top;
	ast->var_cache.pop_bounds[stack_top] = ast->var_cache.current_entry;
	if (access_previous_frame) {
		ast->var_cache.search_bounds[stack_top] = ast->var_cache.search_bounds[stack_top - 1];
		if (ast->var_cache.return_type_count)
			ast->var_cache.return_types[ast->var_cache.return_type_count] = ast->var_cache.return_types[ast->var_cache.return_type_count - 1];
		else
			ast->var_cache.return_types[ast->var_cache.return_type_count] = NULL;
		ast->var_cache.return_type_count++;
	}
	else {
		ast->var_cache.search_bounds[stack_top] = ast->var_cache.current_entry;
		ast->var_cache.return_types[ast->var_cache.return_type_count++] = return_type;
	}
}

static void ast_var_cache_close_frame(ast_t* ast) {
	ast->var_cache.current_entry = ast->var_cache.pop_bounds[ast->var_cache.stack_top];
	ast->var_cache.stack_top--;
	ast->var_cache.return_type_count--;
}

static const int ast_var_cache_decl_var(ast_t* ast, uint64_t id_hash, ast_var_info_t var_info, int global) {
	if (global) {
		for (uint_fast8_t i = 0; i < ast->var_cache.global_entry_count; i++)
			if (ast->var_cache.global_entries[i].id_hash == id_hash)
				return 0;
		ast->var_cache.global_entries[ast->var_cache.global_entry_count++] = (ast_var_cache_entry_t){
			.id_hash = id_hash,
			.var_info = var_info
		};
	}
	else {
		for (int_fast16_t i = ast->var_cache.current_entry - 1; i >= ast->var_cache.search_bounds[ast->var_cache.stack_top]; i--)
			if (ast->var_cache.entries[i].id_hash == id_hash)
				return 0;
		ast->var_cache.entries[ast->var_cache.current_entry++] = (ast_var_cache_entry_t){
			.id_hash = id_hash,
			.var_info = var_info
		};
	}
	return 1;
}

static const int ast_var_cache_find_info(ast_t* ast, uint64_t id_hash, ast_var_info_t* info_out) {
	for (int_fast16_t i = ast->var_cache.current_entry - 1; i >= ast->var_cache.search_bounds[ast->var_cache.stack_top]; i--)
		if (ast->var_cache.entries[i].id_hash == id_hash) {
			*info_out = ast->var_cache.entries[i].var_info;
			return 1;
		}
	for (uint_fast8_t i = 0; i < ast->var_cache.global_entry_count; i++)
		if (ast->var_cache.global_entries[i].id_hash == id_hash) {
			*info_out = ast->var_cache.global_entries[i].var_info;
			return 1;
		}
	return 0;
}

static const int init_ast_code_block(ast_code_block_t* code_block) {
	code_block->instruction_count = 0;
	ESCAPE_ON_NULL(code_block->instructions = malloc((code_block->allocated_instructions = 16) * sizeof(ast_top_level_t)));
	return 1;
}

static void free_ast_array_lit(ast_array_literal_t* array_literal) {
	for (uint32_t i = 0; i < array_literal->element_count; i++)
		free_ast_value(&array_literal->elements[i]);
	free(array_literal->elements);
	free_typecheck_type(&array_literal->elem_type);
}

static void free_ast_call_proc(ast_call_proc_t* call_proc) {
	for (uint_fast8_t i = 0; i < call_proc->argument_count; i++)
		free_ast_value(&call_proc->arguments[i]);
	free_ast_value(&call_proc->procedure);
}

static void free_ast_value(ast_value_t* value) {
	free_typecheck_type(&value->type);
	switch (value->value_type)
	{
	case AST_VALUE_ALLOC_ARRAY:
		free_typecheck_type(&value->data.alloc_array->elem_type);
		free_ast_value(&value->data.alloc_array->size);
		free(value->data.alloc_array);
		break;
	case AST_VALUE_ARRAY_LITERAL:
		free_ast_array_lit(&value->data.array_literal);
		break;
	case AST_VALUE_PROC:
		free_typecheck_type(&value->data.procedure->return_type);
		free_ast_code_block(&value->data.procedure->exec_block);
		free(value->data.procedure);
		break;
	case AST_VALUE_GET_INDEX:
		free_ast_value(&value->data.get_index->array);
		free_ast_value(&value->data.get_index->index);
		free(value->data.get_index);
		break;
	case AST_VALUE_SET_VAR:
		free_ast_value(&value->data.set_var->set_value);
		free(value->data.set_var);
		break;
	case AST_VALUE_SET_INDEX:
		free_ast_value(&value->data.set_index->array);
		free_ast_value(&value->data.set_index->index);
		free_ast_value(&value->data.set_index->value);
		free(value->data.set_index);
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
		free_ast_call_proc(value->data.proc_call);
		free(value->data.proc_call);
		break;
	}
}

static void free_ast_conditional(ast_cond_t* conditional) {
	if (conditional->has_cond_val)
		free_ast_value(&conditional->cond_val);
	free_ast_code_block(&conditional->exec_block);
	if (conditional->next_if_true && conditional->next_if_true != conditional)
		free_ast_conditional(conditional->next_if_true);
	if (conditional->next_if_false && conditional->next_if_false != conditional)
		free_ast_conditional(conditional->next_if_false);
	free(conditional);
}

static void free_ast_top_lvl(ast_top_level_t top_level_ins) {
	switch (top_level_ins.type) {
	case AST_TOP_LEVEL_RETURN_VALUE:
	case AST_TOP_LEVEL_VALUE:
		free_ast_value(&top_level_ins.data.value);
		break;
	case AST_TOP_LEVEL_DECL_VAR:
		free_typecheck_type(&top_level_ins.data.var_decl.var_info.type);
		free_ast_value(&top_level_ins.data.var_decl.set_value);
		break;
	case AST_TOP_LEVEL_COND:
		free_ast_conditional(top_level_ins.data.conditional);
		break;
	case AST_TOP_LEVEL_FOREIGN: {
		free_ast_value(&top_level_ins.data.foreign.id_t);
		if (top_level_ins.data.foreign.has_input)
			free_ast_value(&top_level_ins.data.foreign.input);
		break; 
	}
	}
}

static void free_ast_code_block(ast_code_block_t* code_block) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++)
		free_ast_top_lvl(code_block->instructions[i]);
	free(code_block->instructions);
}

static const int ast_code_block_append_ins(ast_code_block_t* code_block, ast_top_level_t instruction) {
	if (code_block->instruction_count == code_block->allocated_instructions) {
		code_block->allocated_instructions *= 2;
		ast_top_level_t* new_instructions = realloc(code_block->instructions, code_block->allocated_instructions * sizeof(ast_top_level_t));
		ESCAPE_ON_NULL(new_instructions);
		code_block->instructions = new_instructions;
	}
	code_block->instructions[code_block->instruction_count++] = instruction;
	return 1;
}

static const int parse_id(ast_t* ast, ast_id_t* id) {
	MATCH_TOK(TOK_IDENTIFIER);
	id->c_str = LAST_TOK.str;
	id->length = LAST_TOK.length;
	id->hash = hash_s(id->c_str, id->length);
	READ_TOK;
	return 1;
}

static const int parse_type_decl(ast_t* ast, typecheck_type_t* typecheck_type, int allow_auto, int allow_nothing, int allow_define_typearg) {
	switch (LAST_TOK.type)
	{
	case TOK_TYPECHECK_BOOL:
		typecheck_type->type = TYPE_PRIMATIVE_BOOL;
		break;
	case TOK_TYPECHECK_CHAR:
		typecheck_type->type = TYPE_PRIMATIVE_CHAR;
		break;
	case TOK_TYPECHECK_LONG:
		typecheck_type->type = TYPE_PRIMATIVE_LONG;
		break;
	case TOK_TYPECHECK_FLOAT:
		typecheck_type->type = TYPE_PRIMATIVE_FLOAT;
		break;
	case TOK_TYPECHECK_ARRAY:
		typecheck_type->type = TYPE_SUPER_ARRAY;
		break;
	case TOK_TYPECHECK_PROC:
		typecheck_type->type = TYPE_SUPER_PROC;
		break;
	case TOK_AUTO:
		if (allow_auto)
			typecheck_type->type = TYPE_AUTO;
		else
			PANIC(ast, ERROR_TYPE_NOT_ALLOWED);
		break;
	case TOK_NOTHING:
		if (allow_nothing)
			typecheck_type->type = TYPE_NOTHING;
		else
			PANIC(ast, ERROR_TYPE_NOT_ALLOWED);
		break;
	case TOK_TYPEARG: {
		typecheck_type->type = TYPE_TYPEARG;
		READ_TOK;
		ast_id_t id;
		ESCAPE_ON_NULL(parse_id(ast, &id));

		for (int_fast16_t i = ast->generic_cache.decl_count - 1; i >= ast->generic_cache.search_bounds[ast->generic_cache.stack_top]; i--) {
			if (ast->generic_cache.ids[i] == id.hash) {
				typecheck_type->match = i;
				goto escape;
			}
		}
		PANIC_ON_NULL(allow_define_typearg, ast, ERROR_NO_TYPE_ARG);
		typecheck_type->match = ast->generic_cache.decl_count;
		ast->generic_cache.ids[ast->generic_cache.decl_count++] = id.hash;
	escape:
		typecheck_type->match -= ast->generic_cache.search_bounds[ast->generic_cache.stack_top];
		break;
	}
	default:
		PANIC(ast, ERROR_UNEXPECTED_TOK);
	}
	if(typecheck_type->type != TYPE_TYPEARG)
		READ_TOK;
	if (LAST_TOK.type == TOK_LESS) {
		typecheck_type_t sub_types[TYPE_MAX_SUBTYPES];
		uint8_t found_sub_types = 0;
		do {
			if (found_sub_types == TYPE_MAX_SUBTYPES)
				PANIC(ast, ERROR_TO_MANY_SUB_TYPES);
			READ_TOK;
			ESCAPE_ON_NULL(parse_type_decl(ast, &sub_types[found_sub_types++], 0, typecheck_type->type == TYPE_SUPER_PROC && found_sub_types == 0, allow_define_typearg));
		} while (LAST_TOK.type == TOK_COMMA);
		MATCH_TOK(TOK_MORE);
		READ_TOK;

		if (typecheck_type->type == TYPE_SUPER_ARRAY && found_sub_types != 1)
			PANIC(ast, ERROR_TO_MANY_SUB_TYPES);

		typecheck_type->sub_types = malloc((typecheck_type->sub_type_count = found_sub_types) * sizeof(typecheck_type_t));

		for (uint_fast8_t i = 0; i < found_sub_types; i++)
			typecheck_type->sub_types[i] = sub_types[i];
	}
	else if (typecheck_type->type >= TYPE_SUPER_ARRAY)
		PANIC(ast, ERROR_EXPECTED_SUB_TYPES)
	else {
		typecheck_type->sub_type_count = 0;
		typecheck_type->sub_types = NULL;
	}
	return 1;
}

static const int parse_var_decl(ast_t* ast, ast_decl_var_t* var_decl, uint16_t* current_reg, uint16_t* register_limit) {
	if (LAST_TOK.type == TOK_GLOBAL) {
		var_decl->global_flag = 1;
		READ_TOK;
	}
	else
		var_decl->global_flag = 0;
	ESCAPE_ON_NULL(parse_type_decl(ast, &var_decl->var_info.type, 1, 0, 0));
	ESCAPE_ON_NULL(parse_id(ast, &var_decl->id));

	MATCH_TOK(TOK_SET);
	READ_TOK;

	ESCAPE_ON_NULL(parse_expression(ast, &var_decl->set_value, 0));

	if (var_decl->var_info.type.type == TYPE_AUTO) {
		free_typecheck_type(&var_decl->var_info.type);
		PANIC_ON_NULL(copy_typecheck_type(&var_decl->var_info.type, var_decl->set_value.type), ast, ERROR_MEMORY);
	}
	else if (!typecheck_type_compatible(var_decl->var_info.type, var_decl->set_value.type))
		PANIC(ast, ERROR_UNEXPECTED_TYPE);
	var_decl->var_info.alloced_reg.offset_flag = !var_decl->global_flag;
	var_decl->var_info.is_global = var_decl->global_flag;
	if (var_decl->global_flag)
		var_decl->var_info.alloced_reg.index = ast->global_registers++;
	else {
		var_decl->var_info.alloced_reg.index = *current_reg;
		(*current_reg)++;
		(*register_limit)++;
	}
	ESCAPE_ON_NULL(ast_var_cache_decl_var(ast, var_decl->id.hash, var_decl->var_info, var_decl->global_flag));
	return 1;
}

static const int parse_cond_expr(ast_t* ast, ast_value_t* cond_expr) {
	MATCH_TOK(TOK_OPEN_PAREN);
	READ_TOK;
	ESCAPE_ON_NULL(parse_expression(ast, cond_expr, 0));
	if (cond_expr->type.type != TYPE_PRIMATIVE_BOOL)
		PANIC(ast, ERROR_UNEXPECTED_TYPE);
	MATCH_TOK(TOK_CLOSE_PAREN);
	READ_TOK;
	return 1;
}

static const int parse_conditional(ast_t* ast, ast_cond_t* conditional, uint16_t* current_reg, uint16_t* register_limit, int top_level) {
	uint16_t old_reg = *current_reg;
	if (LAST_TOK.type == TOK_IF) {
		READ_TOK;
		ESCAPE_ON_NULL(parse_cond_expr(ast, &conditional->cond_val));

		ast_var_cache_new_frame(ast, NULL, 1);

		uint16_t block_limit;

		init_ast_code_block(&conditional->exec_block);
		ESCAPE_ON_NULL(parse_code_block(ast, &conditional->exec_block, current_reg, register_limit, 1, top_level));
		(*current_reg) = old_reg;
		ast_var_cache_close_frame(ast);

		conditional->next_if_true = NULL;
		conditional->has_cond_val = 1;
		if (LAST_TOK.type == TOK_ELSE)
		{
			READ_TOK;
			if (LAST_TOK.type == TOK_IF) {
				block_limit = *register_limit;
				PANIC_ON_NULL(conditional->next_if_false = malloc(sizeof(ast_cond_t)), ast, ERROR_MEMORY);
				ESCAPE_ON_NULL(parse_conditional(ast, conditional->next_if_false, current_reg, &block_limit, top_level));
				*register_limit = max(block_limit, *register_limit);
				conditional = conditional->next_if_false;
			}
			else {
				PANIC_ON_NULL(conditional->next_if_false = malloc(sizeof(ast_cond_t)), ast, ERROR_MEMORY);
				conditional = conditional->next_if_false;
				conditional->next_if_true = NULL;
				conditional->next_if_false = NULL;
				conditional->has_cond_val = 0;

				block_limit = *register_limit;
				ast_var_cache_new_frame(ast, NULL, 1);
				init_ast_code_block(&conditional->exec_block);
				ESCAPE_ON_NULL(parse_code_block(ast, &conditional->exec_block, current_reg, &block_limit, 1, top_level));
				*register_limit = max(block_limit, *register_limit);
				(*current_reg) = old_reg;
				ast_var_cache_close_frame(ast);
			}
		}
		else
			conditional->next_if_false = NULL;
	}
	else if (LAST_TOK.type == TOK_WHILE) {
		READ_TOK;
		conditional->next_if_true = conditional;
		conditional->next_if_false = NULL;
		conditional->has_cond_val = 1;

		ESCAPE_ON_NULL(parse_cond_expr(ast, &conditional->cond_val));

		ast_var_cache_new_frame(ast, NULL, 1);
		init_ast_code_block(&conditional->exec_block);
		ESCAPE_ON_NULL(parse_code_block(ast, &conditional->exec_block, current_reg, register_limit, 1, top_level));
		(*current_reg) = old_reg;
		ast_var_cache_close_frame(ast);
	}
	else
		PANIC(ast, ERROR_UNEXPECTED_TOK);
	return 1;
}

static const int parse_array_lit(ast_t* ast, ast_value_t* value) {
	value->value_type = AST_VALUE_ARRAY_LITERAL;
	MATCH_TOK(TOK_OPEN_BRACKET);

	uint32_t allocated_values = 64;
	PANIC_ON_NULL(value->data.array_literal.elements = malloc(allocated_values * sizeof(ast_value_t)), ast, ERROR_MEMORY);
	value->data.array_literal.element_count = 0;

	int type_flag = 0;
	do {
		READ_TOK;
		if (value->data.array_literal.element_count == allocated_values) {
			allocated_values *= 2;
			ast_value_t* new_elements = realloc(value->data.array_literal.elements, allocated_values * sizeof(ast_value_t));
			PANIC_ON_NULL(new_elements, ast, ERROR_MEMORY);
			value->data.array_literal.elements = new_elements;
		}
		ast_value_t* elem = &value->data.array_literal.elements[value->data.array_literal.element_count++];
		ESCAPE_ON_NULL(parse_expression(ast, elem, 0));

		if (type_flag) {
			if (!typecheck_type_compatible(value->data.array_literal.elem_type, elem->type))
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
		}
		else {
			PANIC_ON_NULL(copy_typecheck_type(&value->data.array_literal.elem_type, elem->type), ast, ERROR_MEMORY);
			type_flag = 1;
		}
	} while (LAST_TOK.type == TOK_COMMA);

	MATCH_TOK(TOK_CLOSE_BRACKET);
	READ_TOK;

	value->type = (typecheck_type_t){
		.type = TYPE_SUPER_ARRAY,
		.sub_type_count = 1,
	};
	PANIC_ON_NULL(value->type.sub_types = malloc(sizeof(typecheck_type_t)), ast, ERROR_MEMORY);
	PANIC_ON_NULL(copy_typecheck_type(&value->type.sub_types[0], value->data.array_literal.elem_type), ast, ERROR_MEMORY);

	return 1;
}

static const int parse_prim_value(ast_t* ast, ast_value_t* value) {
	switch (LAST_TOK.type)
	{
	case TOK_NUMERICAL: {
		for (uint_fast32_t i = 0; i < LAST_TOK.length; i++)
			if (LAST_TOK.str[i] == '.' || LAST_TOK.str[i] == 'f') { //is a float
				value->data.float_int = strtod(LAST_TOK.str, NULL);
				value->value_type = AST_VALUE_FLOAT;
				value->type = (typecheck_type_t){
					.type = TYPE_PRIMATIVE_FLOAT,
					.sub_type_count = 0,
					.sub_types = NULL
				};
				READ_TOK;
				return 1;
			}
		value->value_type = AST_VALUE_LONG;
		value->data.long_int = strtol(LAST_TOK.str, NULL, 10);
		value->type = (typecheck_type_t){
			.type = TYPE_PRIMATIVE_LONG,
			.sub_type_count = 0,
			.sub_types = NULL
		};
		READ_TOK;
		return 1;
	}
	case TOK_CHAR: {
		value->value_type = AST_VALUE_CHAR;
		scanner_t temp_scanner;
		init_scanner(&temp_scanner, LAST_TOK.str, LAST_TOK.length, 0);

		scanner_scan_char(&temp_scanner);
		value->data.character = temp_scanner.last_char;
		value->type = (typecheck_type_t){
			.type = TYPE_PRIMATIVE_CHAR,
			.sub_type_count = 0,
			.sub_types = NULL
		};
		READ_TOK;
		return 1;
	}
	case TOK_STRING: {
		value->value_type = AST_VALUE_ARRAY_LITERAL;
		value->type = (typecheck_type_t){
			.type = TYPE_SUPER_ARRAY,
			.sub_type_count = 1,
		};
		PANIC_ON_NULL(value->type.sub_types = malloc(sizeof(typecheck_type_t)), ast, ERROR_MEMORY);
		value->data.array_literal.elem_type = value->type.sub_types[0] = (typecheck_type_t){
			.type = TYPE_PRIMATIVE_CHAR,
			.sub_type_count = 0,
			.sub_types = NULL
		};
		char* str_buf = malloc(LAST_TOK.length * sizeof(char));
		uint32_t str_buf_size = 0;
		scanner_t temp_scanner;
		init_scanner(&temp_scanner, LAST_TOK.str, LAST_TOK.length, 0);
		do {
			scanner_scan_char(&temp_scanner);
			str_buf[str_buf_size++] = temp_scanner.last_char;
		} while (temp_scanner.last_char);
		--str_buf_size;

		value->data.array_literal.element_count = str_buf_size;
		PANIC_ON_NULL(value->data.array_literal.elements = malloc(str_buf_size * sizeof(ast_value_t)),ast, ERROR_MEMORY);
		for (uint_fast32_t i = 0; i < str_buf_size; i++)
			value->data.array_literal.elements[i] = (ast_value_t){
				.value_type = AST_VALUE_CHAR,
				.data.character = str_buf[i],
				.type = value->data.array_literal.elem_type
		};
		free(str_buf);
		READ_TOK;
		return 1;
	}
	case TOK_TRUE:
	case TOK_FALSE: {
		value->value_type = AST_VALUE_BOOL;
		value->type = (typecheck_type_t){
			.type = TYPE_PRIMATIVE_BOOL,
			.sub_type_count = 0,
			.sub_types = NULL
		};
		value->data.bool_flag = LAST_TOK.type == TOK_TRUE;
		READ_TOK;
		return 1; 
	}
	case TOK_OPEN_BRACKET:
		return parse_array_lit(ast, value);
	case TOK_NEW: {
		value->value_type = AST_VALUE_ALLOC_ARRAY;
		READ_TOK;
		PANIC_ON_NULL(value->data.alloc_array = malloc(sizeof(ast_alloc_t)), ast, ERROR_MEMORY);
		ESCAPE_ON_NULL(parse_type_decl(ast, &value->data.alloc_array->elem_type, 0, 0, 0));
		PANIC_ON_NULL(value->type.sub_types = malloc((value->type.sub_type_count = 1) * sizeof(typecheck_type_t)), ast, ERROR_MEMORY);
		PANIC_ON_NULL(copy_typecheck_type(&value->type.sub_types[0], value->data.alloc_array->elem_type), ast, ERROR_MEMORY);
		value->type.type = TYPE_SUPER_ARRAY;

		MATCH_TOK(TOK_OPEN_BRACKET);
		READ_TOK;
		
		ESCAPE_ON_NULL(parse_expression(ast, &value->data.alloc_array->size, 0));
		if (value->data.alloc_array->size.type.type != TYPE_PRIMATIVE_LONG)
			PANIC(ast, ERROR_UNEXPECTED_TYPE);

		MATCH_TOK(TOK_CLOSE_BRACKET);
		READ_TOK;
		return 1;
	}
	}
	PANIC(ast, ERROR_UNEXPECTED_TOK);
}

static const int parse_proc_lit(ast_t* ast, ast_value_t* value) {
	value->value_type = AST_VALUE_PROC;
	PANIC_ON_NULL(value->data.procedure = malloc(sizeof(ast_proc_t)), ast, ERROR_MEMORY);
	value->data.procedure->param_count = 0;
	MATCH_TOK(TOK_OPEN_PAREN);

	uint16_t current_reg = 1;
	value->data.procedure->exec_block.register_limit = 1;
	ast->generic_cache.search_bounds[++ast->generic_cache.stack_top] = ast->generic_cache.decl_count;
	ast_var_cache_new_frame(ast, NULL, 0);

	do {
		READ_TOK;
		if (LAST_TOK.type == TOK_CLOSE_PAREN)
			break;
		if (value->data.procedure->param_count == TYPE_MAX_SUBTYPES - 1)
			PANIC(ast, ERROR_TO_MANY_SUB_TYPES);
		struct ast_proc_param* param = &value->data.procedure->params[value->data.procedure->param_count++];
		ESCAPE_ON_NULL(parse_type_decl(ast, &param->var_info.type, 0, 0, 1));
		ESCAPE_ON_NULL(parse_id(ast, &param->id));

		param->var_info.alloced_reg.index = current_reg++;
		param->var_info.alloced_reg.offset_flag = 1;
		ast_var_cache_decl_var(ast, param->id.hash, param->var_info, 0);
		value->data.procedure->exec_block.register_limit++;
	} while (LAST_TOK.type == TOK_COMMA);
	MATCH_TOK(TOK_CLOSE_PAREN);
	READ_TOK;
	MATCH_TOK(TOK_RETURN);
	READ_TOK;

	ESCAPE_ON_NULL(parse_type_decl(ast, &value->data.procedure->return_type, 1, 1, 0));
	

	value->type = (typecheck_type_t){
		.type = TYPE_SUPER_PROC,
		.sub_type_count = 1 + value->data.procedure->param_count
	};

	PANIC_ON_NULL(value->type.sub_types = malloc(value->type.sub_type_count * sizeof(typecheck_type_t)), ast, ERROR_MEMORY);
	PANIC_ON_NULL(copy_typecheck_type(&value->type.sub_types[0], value->data.procedure->return_type), ast, ERROR_MEMORY);
	for (uint_fast8_t i = 0; i < value->data.procedure->param_count; i++)
		value->type.sub_types[i + 1] = value->data.procedure->params[i].var_info.type;
	ast->var_cache.return_types[ast->var_cache.return_type_count - 1] = &value->type.sub_types[0];

	PANIC_ON_NULL(ast_var_cache_decl_var(ast, 7572967076558961, (ast_var_info_t) { .alloced_reg = (ast_reg_t){ .index = current_reg++, .offset_flag = 1 }, .type = value->type }, 0), ast, ERROR_MEMORY);
	value->data.procedure->exec_block.register_limit++;

	init_ast_code_block(&value->data.procedure->exec_block);
	ESCAPE_ON_NULL(parse_code_block(ast, &value->data.procedure->exec_block, &current_reg, &value->data.procedure->exec_block.register_limit, 1, 0));
	free_typecheck_type(&value->data.procedure->return_type);
	PANIC_ON_NULL(copy_typecheck_type(&value->data.procedure->return_type, value->type.sub_types[0]), ast, ERROR_MEMORY);

	ast_var_cache_close_frame(ast);
	ast->generic_cache.stack_top--;

	return 1;
}

static const int parse_code_block(ast_t* ast, ast_code_block_t* code_block, uint16_t* current_reg, uint16_t* register_limit, int encapsulated, int top_level) {
	if (encapsulated) {
		MATCH_TOK(TOK_OPEN_BRACE);
		READ_TOK;
	}

	do {
		ast_top_level_t top_level_ins;
		switch (LAST_TOK.type)
		{
		case TOK_AUTO:
		case TOK_NOTHING: //nothing will generate an error
		case TOK_GLOBAL:
		case TOK_TYPECHECK_ARRAY:
		case TOK_TYPECHECK_BOOL:
		case TOK_TYPECHECK_CHAR:
		case TOK_TYPECHECK_FLOAT:
		case TOK_TYPECHECK_LONG:
		case TOK_TYPECHECK_PROC:{
			ESCAPE_ON_NULL(parse_var_decl(ast, &top_level_ins.data.var_decl, current_reg, register_limit));
			top_level_ins.type = AST_TOP_LEVEL_DECL_VAR;
			break;
		}
		case TOK_IDENTIFIER: { 
			ESCAPE_ON_NULL(parse_value(ast, &top_level_ins.data.value));
			if (top_level_ins.data.value.value_type != AST_VALUE_SET_INDEX && top_level_ins.data.value.value_type != AST_VALUE_SET_VAR &&
				top_level_ins.data.value.value_type != AST_VALUE_PROC_CALL)
				PANIC(ast, ERROR_UNEXPECTED_TOK);
			top_level_ins.type = AST_TOP_LEVEL_VALUE;
			break;
		}
		case TOK_RETURN: {
			READ_TOK;
			if (top_level)
				PANIC(ast, ERROR_CANNOT_RETURN);
			if (LAST_TOK.type == TOK_SEMICOLON)
				top_level_ins.type = AST_TOP_LEVEL_RETURN;
			else {
				top_level_ins.type = AST_TOP_LEVEL_RETURN_VALUE;
				ESCAPE_ON_NULL(parse_expression(ast, &top_level_ins.data.value, 0));

				typecheck_type_t* return_type = ast->var_cache.return_types[ast->var_cache.return_type_count - 1];
				if (return_type->type == TYPE_AUTO) {
					free_typecheck_type(return_type);
					copy_typecheck_type(return_type, top_level_ins.data.value.type);
				}
				else if (!typecheck_type_compatible(*return_type, top_level_ins.data.value.type))
					PANIC(ast, ERROR_UNEXPECTED_TYPE);
			}
			break;
		}
		case TOK_BREAK:
		case TOK_CONTINUE:
			top_level_ins.type = AST_TOP_LEVEL_CONTINUE + LAST_TOK.type - TOK_CONTINUE;
			READ_TOK;
			break;
		case TOK_IF:
		case TOK_WHILE: {
			top_level_ins.type = AST_TOP_LEVEL_COND;
			PANIC_ON_NULL(top_level_ins.data.conditional = malloc(sizeof(ast_cond_t)), ast, ERROR_MEMORY);
			ESCAPE_ON_NULL(parse_conditional(ast, top_level_ins.data.conditional, current_reg, register_limit, top_level)); 
			break;
		}
		case TOK_INCLUDE: {
			READ_TOK;
			MATCH_TOK(TOK_STRING);
			
			uint64_t check_hash = hash_s(LAST_TOK.str, LAST_TOK.length);
			for(uint_fast8_t i = 0; i < ast->include_stack.visited_files; i++)
				if (check_hash == ast->include_stack.visited_hashes[i]) {
					READ_TOK;
					goto escape;
				}
			ast->include_stack.visited_hashes[ast->include_stack.visited_files++] = check_hash;

			ast->include_stack.file_paths[ast->include_stack.current_scanner] = malloc((LAST_TOK.length + 1)* sizeof(char));
			PANIC_ON_NULL(ast->include_stack.file_paths[ast->include_stack.current_scanner], ast, ERROR_MEMORY);
			memcpy(ast->include_stack.file_paths[ast->include_stack.current_scanner], LAST_TOK.str, (LAST_TOK.length + 1) * sizeof(char));
			ast->include_stack.file_paths[ast->include_stack.current_scanner][LAST_TOK.length] = 0;
			READ_TOK;
			
			ast->include_stack.sources[ast->include_stack.current_scanner] = file_read_source(ast->include_stack.file_paths[ast->include_stack.current_scanner]);
			PANIC_ON_NULL(ast->include_stack.sources[ast->include_stack.current_scanner], ast, ERROR_CANNOT_OPEN_FILE);
			++ast->include_stack.current_scanner;

			init_scanner(&ast->include_stack.scanners[ast->include_stack.current_scanner], ast->include_stack.sources[ast->include_stack.current_scanner - 1], strlen(ast->include_stack.sources[ast->include_stack.current_scanner - 1]), 1);
			ESCAPE_ON_NULL(parse_code_block(ast, code_block, current_reg, register_limit, 0, 1));
			--ast->include_stack.current_scanner;

			free(ast->include_stack.sources[ast->include_stack.current_scanner]);
			free(ast->include_stack.file_paths[ast->include_stack.current_scanner]);

		escape:
			if (LAST_TOK.type == TOK_SEMICOLON)
				READ_TOK;

			continue;
		}
		case TOK_FOREIGN: {
			READ_TOK;
			top_level_ins.type = AST_TOP_LEVEL_FOREIGN;
			ESCAPE_ON_NULL(parse_expression(ast, &top_level_ins.data.foreign.id_t, 0));
			if (top_level_ins.data.foreign.id_t.type.type != TYPE_PRIMATIVE_LONG)
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
			if (LAST_TOK.type == TOK_SEMICOLON) {
				top_level_ins.data.foreign.has_input = 0;
				top_level_ins.data.foreign.has_output = 0;
			}
			else {
				top_level_ins.data.foreign.has_input = 1;
				ESCAPE_ON_NULL(parse_expression(ast, &top_level_ins.data.foreign.input, 0));
				if (LAST_TOK.type == TOK_SEMICOLON)
					top_level_ins.data.foreign.has_output = 0;
				else {
					top_level_ins.data.foreign.has_output = 1;
					ast_value_t out_var_value;
					ESCAPE_ON_NULL(parse_value(ast, &out_var_value));
					if (out_var_value.value_type != AST_VALUE_VAR)
						PANIC(ast, ERROR_UNEXPECTED_TYPE);
					top_level_ins.data.foreign.output = out_var_value.alloced_reg;
					free_ast_value(&out_var_value);
				}
			}
			break;
		}
		default:
			PANIC(ast, ERROR_UNEXPECTED_TOK);
		}
		if (top_level_ins.type != AST_TOP_LEVEL_COND) {
			MATCH_TOK(TOK_SEMICOLON);
			READ_TOK;
		}
		
		PANIC_ON_NULL(ast_code_block_append_ins(code_block, top_level_ins), ast, ERROR_MEMORY);
	} while (LAST_TOK.type != TOK_EOF && LAST_TOK.type != TOK_CLOSE_BRACE);
	
	if (encapsulated) {
		MATCH_TOK(TOK_CLOSE_BRACE);
		READ_TOK;
	}

	return 1;
}

static const int parse_value(ast_t* ast, ast_value_t* value) {
	switch (LAST_TOK.type)
	{
	case TOK_TYPECHECK_PROC: {
		READ_TOK;
		ESCAPE_ON_NULL(parse_proc_lit(ast, value)); 
		break;
	}
	case TOK_NUMERICAL:
	case TOK_STRING:
	case TOK_CHAR:
	case TOK_TRUE:
	case TOK_FALSE:
	case TOK_OPEN_BRACKET:
	case TOK_NEW:
		return parse_prim_value(ast, value);
	case TOK_NOT:
	case TOK_SUBTRACT:
	case TOK_HASHTAG: {
		value->value_type = AST_VALUE_UNARY_OP;
		PANIC_ON_NULL(value->data.unary_op = malloc(sizeof(ast_unary_op_t)), ast, ERROR_MEMORY);
		value->data.unary_op->operator = LAST_TOK.type;
		READ_TOK;
		ESCAPE_ON_NULL(parse_value(ast, &value->data.unary_op->operand));
		if ((LAST_TOK.type == TOK_NOT && value->data.unary_op->operand.type.type != TYPE_PRIMATIVE_BOOL) ||
			(LAST_TOK.type == TOK_HASHTAG && value->data.unary_op->operand.type.type != TYPE_SUPER_ARRAY) ||
			(LAST_TOK.type == TOK_SUBTRACT && value->data.unary_op->operand.type.type != TYPE_PRIMATIVE_FLOAT && value->data.unary_op->operand.type.type != TYPE_PRIMATIVE_LONG))
			PANIC(ast, ERROR_UNEXPECTED_TYPE);
		if (value->data.unary_op->operator == TOK_HASHTAG)
			value->type = (typecheck_type_t){
				.type = TYPE_PRIMATIVE_LONG,
				.sub_type_count = 0,
				.sub_types = NULL
			};
		else
			copy_typecheck_type(&value->type, value->data.unary_op->operand.type);
		break;
	}
	case TOK_IDENTIFIER: {
		ast_id_t id;
		parse_id(ast, &id);

		ast_var_info_t var_info;
		if (!ast_var_cache_find_info(ast, id.hash, &var_info))
			PANIC(ast, ERROR_UNDECLARED_VAR);

		if (LAST_TOK.type == TOK_SET) {
			READ_TOK;
			value->value_type = AST_VALUE_SET_VAR;
			PANIC_ON_NULL(value->data.set_var = malloc(sizeof(ast_set_var_t)), ast, ERROR_MEMORY);
			value->data.set_var->id = id;
			value->data.set_var->set_global = var_info.is_global;

			ESCAPE_ON_NULL(parse_expression(ast, &value->data.set_var->set_value, 0));

			if(!typecheck_type_compatible(var_info.type, value->data.set_var->set_value.type))
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
			copy_typecheck_type(&value->type, var_info.type);
			value->alloced_reg = var_info.alloced_reg;
		}
		else {
			value->value_type = AST_VALUE_VAR;
			value->data.variable = id;
			value->alloced_reg = var_info.alloced_reg;
			copy_typecheck_type(&value->type, var_info.type);
		}
		break;
	}
	case TOK_OPEN_PAREN:
		READ_TOK;
		parse_expression(ast, value, 0);
		MATCH_TOK(TOK_CLOSE_PAREN);
		READ_TOK;
		break;
	default:
		PANIC(ast, ERROR_UNEXPECTED_TOK);
	}
	while (LAST_TOK.type == TOK_OPEN_BRACKET || LAST_TOK.type == TOK_OPEN_PAREN) {
		switch (LAST_TOK.type)
		{
		case TOK_OPEN_BRACKET: {
			READ_TOK;
			ast_value_t index_value;
			ESCAPE_ON_NULL(parse_expression(ast, &index_value, 0));
			if (index_value.type.type != TYPE_PRIMATIVE_LONG || value->type.type != TYPE_SUPER_ARRAY)
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
			ast_value_t array_value = *value;

			MATCH_TOK(TOK_CLOSE_BRACKET);
			READ_TOK;
			
			if (LAST_TOK.type == TOK_SET) {
				READ_TOK;

				ast_value_t set_val;
				ESCAPE_ON_NULL(parse_expression(ast, &set_val, 0));

				if (!typecheck_type_compatible(array_value.type.sub_types[0], set_val.type))
					PANIC(ast, ERROR_UNEXPECTED_TYPE);

				value->value_type = AST_VALUE_SET_INDEX;
				copy_typecheck_type(&value->type, array_value.type.sub_types[0]);

				PANIC_ON_NULL(value->data.set_index = malloc(sizeof(ast_set_index_t)), ast, ERROR_MEMORY);
				*value->data.set_index = (ast_set_index_t){
					.array = array_value,
					.index = index_value,
					.value = set_val
				};
			}
			else {
				value->value_type = AST_VALUE_GET_INDEX;
				copy_typecheck_type(&value->type, array_value.type.sub_types[0]);

				PANIC_ON_NULL(value->data.get_index = malloc(sizeof(ast_get_index_t)), ast, ERROR_MEMORY);
				*value->data.get_index = (ast_get_index_t){
					.array = array_value,
					.index = index_value
				};
			}
			continue;
		}
		case TOK_OPEN_PAREN: {
			if(value->type.type != TYPE_SUPER_PROC)
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
			ast_value_t proc_call_val = {
				.value_type = AST_VALUE_PROC_CALL,
			};
			PANIC_ON_NULL(proc_call_val.data.proc_call = malloc(sizeof(ast_call_proc_t)), ast, ERROR_MEMORY);
			
			ast_call_proc_t* proc_call = proc_call_val.data.proc_call;
			proc_call->procedure = *value;
			proc_call->argument_count = 0;

			type_matcher_t matcher;
			init_type_matcher(&matcher, value->type);

			do {
				READ_TOK;
				if (LAST_TOK.type == TOK_CLOSE_PAREN)
					break;
				if (proc_call->argument_count == value->type.sub_type_count - 1)
					PANIC(ast, ERROR_UNEXPECTED_ARGUMENT_LENGTH);
				
				ESCAPE_ON_NULL(parse_expression(ast, &proc_call->arguments[proc_call->argument_count++], 0));
				PANIC_ON_NULL(type_matcher_add(&matcher, &matcher.out_type.sub_types[proc_call->argument_count], proc_call->arguments[proc_call->argument_count - 1].type), ast, ERROR_UNEXPECTED_TYPE);
			} while (LAST_TOK.type == TOK_COMMA);
			
			if (proc_call->argument_count != value->type.sub_type_count - 1)
				PANIC(ast, ERROR_UNEXPECTED_ARGUMENT_LENGTH);
			
			MATCH_TOK(TOK_CLOSE_PAREN);
			READ_TOK;

			type_matcher_finalize(&matcher);
			PANIC_ON_NULL(copy_typecheck_type(&proc_call_val.type, matcher.out_type.sub_types[0]), ast, ERROR_MEMORY);
			free_type_matcher(&matcher);

			*value = proc_call_val;
			continue;
		}
		}
	}
	return 1;
}

static const int parse_expression(ast_t* ast, ast_value_t* value, int min_prec) {
	ast_value_t lhs;
	ESCAPE_ON_NULL(parse_value(ast, &lhs));

	while (LAST_TOK.type >= TOK_EQUALS && LAST_TOK.type <= TOK_OR && op_precs[LAST_TOK.type - TOK_EQUALS] > min_prec)
	{
		token_type_t op_tok = LAST_TOK.type;
		READ_TOK;

		ast_value_t rhs;
		ESCAPE_ON_NULL(parse_expression(ast, &rhs, op_precs[op_tok - TOK_EQUALS]));
		if (op_tok == TOK_AND || op_tok == TOK_OR) {
			if (lhs.type.type != TYPE_PRIMATIVE_BOOL || rhs.type.type != TYPE_PRIMATIVE_BOOL)
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
		}
		else if (op_tok > TOK_NOT_EQUAL) {
			if ((lhs.type.type != TYPE_PRIMATIVE_FLOAT && lhs.type.type != TYPE_PRIMATIVE_LONG) ||
				(rhs.type.type != TYPE_PRIMATIVE_FLOAT && rhs.type.type != TYPE_PRIMATIVE_LONG))
				PANIC(ast, ERROR_UNEXPECTED_TYPE);
		} 
		else if(lhs.type.type != TYPE_SUPER_PROC && lhs.type.type != TYPE_SUPER_ARRAY &&
			rhs.type.type != TYPE_SUPER_PROC && rhs.type.type != TYPE_SUPER_ARRAY && !typecheck_type_compatible(lhs.type, rhs.type))
			PANIC(ast, ERROR_UNEXPECTED_TYPE);

		ast_value_t bin_op = {
			.value_type = AST_VALUE_BINARY_OP,
		};
		PANIC_ON_NULL(bin_op.data.binary_op = malloc(sizeof(ast_binary_op_t)), ast, ERROR_MEMORY);

		*bin_op.data.binary_op = (ast_binary_op_t){
			.lhs = lhs,
			.rhs = rhs,
			.operator = op_tok
		};

		if (op_tok > TOK_LESS_EQUAL) {
			bin_op.type = (typecheck_type_t){
				.type = max(lhs.type.type, rhs.type.type),
				.sub_type_count = 0,
				.sub_types = NULL
			};
		}
		else {
			bin_op.type = (typecheck_type_t){
				.type = TYPE_PRIMATIVE_BOOL,
				.sub_type_count = 0,
				.sub_types = NULL
			};
		}

		lhs = bin_op;
	}
	*value = lhs;
	return 1;
}

const int init_ast(ast_t* ast, const char* source) {
	ast->last_err = ERROR_NONE;
	ast->generic_cache.stack_top = 0;
	ast->generic_cache.decl_count = 0;
	ast->var_cache.stack_top = 0;
	ast->var_cache.current_entry = 0;
	ast->var_cache.global_entry_count = 0;
	ast->var_cache.return_type_count = 0;
	ast->global_registers = 0;
	ast->generic_cache.search_bounds[0] = 0;
	ast->var_cache.search_bounds[0] = 0;
	ast->var_cache.pop_bounds[0] = 0;
	ast->include_stack.current_scanner = 0;
	ast->include_stack.visited_files = 0;

	init_scanner(&ast->include_stack.scanners[0], source, strlen(source), 1);
	uint16_t current_reg = 0;
	ast->exec_block.register_limit = 0;
	init_ast_code_block(&ast->exec_block);
	ESCAPE_ON_NULL(parse_code_block(ast, &ast->exec_block, &current_reg, &ast->exec_block.register_limit, 0, 1));
	
	return 1;
}

void free_ast(ast_t* ast) {
	for (uint_fast8_t i = ast->include_stack.current_scanner; i > 0; i--) {
		free(ast->include_stack.file_paths[i - 1]);
		free(ast->include_stack.sources[i - 1]);
	}
	free_ast_code_block(&ast->exec_block);
}