#pragma once

#ifndef AST_H
#define AST_H

#include <stdint.h>
#include "type.h"
#include "tokens.h"
#include "scanner.h"

typedef struct ast_value ast_value_t;
typedef struct ast_alloc ast_alloc_t;
typedef struct ast_set_var ast_set_var_t;
typedef struct ast_set_index ast_set_index_t;
typedef struct ast_get_index ast_get_index_t;
typedef struct ast_binary_op ast_binary_op_t;
typedef struct ast_unary_op ast_unary_op_t;
typedef struct ast_call_proc ast_call_proc_t;
typedef struct ast_cond ast_cond_t;
typedef struct ast_proc ast_proc_t;

typedef struct ast_var_info {
	uint16_t id;
	int is_global, is_readonly;
	typecheck_type_t type;
} ast_var_info_t;

typedef struct ast_array_literal {
	typecheck_type_t* elem_type;

	ast_value_t* elements;
	uint32_t element_count;
} ast_array_literal_t;

typedef struct ast_primative {
	enum ast_primative_type {
		AST_PRIMATIVE_BOOL,
		AST_PRIMATIVE_CHAR,
		AST_PRIMATIVE_LONG,
		AST_PRIMATIVE_FLOAT
	} type;

	union ast_primative_data
	{
		int bool_flag;
		char character;
		int64_t long_int;
		double float_int;
	} data;

	uint16_t id;
} ast_primative_t;

typedef struct ast_value {
	typecheck_type_t type;

	enum ast_value_type {
		AST_VALUE_PRIMATIVE,
		AST_VALUE_ALLOC_ARRAY,
		AST_VALUE_ARRAY_LITERAL,
		AST_VALUE_PROC,
		AST_VALUE_VAR,
		AST_VALUE_SET_VAR,
		AST_VALUE_SET_INDEX,
		AST_VALUE_GET_INDEX,
		AST_VALUE_BINARY_OP,
		AST_VALUE_UNARY_OP,
		AST_VALUE_PROC_CALL,
	} value_type;

	union ast_value_data {
		ast_primative_t primative;
		ast_alloc_t* alloc_array;
		ast_array_literal_t array_literal;
		ast_proc_t* procedure;
		ast_var_info_t* variable;
		ast_get_index_t* get_index;
		ast_set_var_t* set_var;
		ast_set_index_t* set_index;
		ast_binary_op_t* binary_op;
		ast_unary_op_t* unary_op;
		ast_call_proc_t* proc_call;
	} data;
} ast_value_t;

typedef struct ast_decl_var {
	ast_var_info_t var_info;
	ast_value_t set_value;
} ast_decl_var_t;

typedef struct ast_set_var {
	ast_var_info_t* var_info;
	ast_value_t set_value;
} set_var_t;

typedef struct ast_alloc {
	typecheck_type_t* elem_type;
	ast_value_t size;
} ast_alloc_t;

typedef struct ast_set_index {
	ast_value_t array, index, value;
} ast_set_index_t;

typedef struct ast_get_index {
	ast_value_t array, index;
} ast_get_index_t;

typedef struct ast_binary_op {
	token_type_t operator;
	ast_value_t lhs, rhs;
} ast_binary_op_t;

typedef struct ast_unary_op {
	token_type_t operator;
	ast_value_t operand;
} ast_unary_op;

typedef struct ast_call_proc {
	ast_value_t procedure;
	
	ast_value_t arguments[TYPE_MAX_SUBTYPES - 1];
	uint8_t argument_count;
} ast_call_proc_t;

typedef struct ast_foreign_call {
	ast_value_t id_t, input;
	ast_var_info_t* output_var;
	int has_input, has_output;
} ast_foreign_call_t;

typedef struct ast_statement {
	enum ast_statement_type {
		AST_STATEMENT_DECL_VAR,
		AST_STATEMENT_COND,
		AST_STATEMENT_VALUE,
		AST_STATEMENT_RETURN_VALUE,
		AST_STATEMENT_RETURN,
		AST_STATEMENT_CONTINUE,
		AST_STATEMENT_BREAK,
		AST_STATEMENT_FOREIGN
	} type;

	union ast_statement_data
	{
		ast_decl_var_t var_decl;
		ast_cond_t* conditional;
		ast_value_t value;
		ast_foreign_call_t foreign;
	} data;
} ast_statement_t;

typedef struct ast_code_block {
	ast_statement_t* instructions;
	uint32_t instruction_count, allocated_instructions;
	uint16_t variables;
} ast_code_block_t;

typedef struct ast_cond {
	ast_value_t condition;
	int has_cond_val;

	ast_code_block_t exec_block;

	ast_cond_t* next_if_true;
	ast_cond_t* next_if_false;
} ast_cond_t;

typedef struct ast_proc {
	typecheck_type_t* return_type;

	struct ast_proc_param {
		ast_var_info_t var_info;
		typecheck_type_t* type;
	} params[TYPE_MAX_SUBTYPES - 1];

	uint8_t param_count;

	ast_code_block_t exec_block;
} ast_proc_t;

typedef struct ast_var_cache_entry {
	uint64_t id_hash;
	ast_var_info_t* var_info;
} ast_var_cache_entry_t;

typedef struct ast {
	ast_code_block_t exec_block;
	uint16_t global_variables, constants;
} ast_t;

const int init_ast(ast_t* ast, const char* source);
void free_ast(ast_t* ast);

#endif // !AST_H