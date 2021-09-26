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
typedef struct ast_struct_proto ast_struct_proto_t;
typedef struct ast_get_property ast_get_property_t;
typedef struct ast_set_property ast_set_property_t;

typedef struct ast_register {
	uint16_t index;
	uint8_t offset_flag;
} ast_reg_t;

typedef struct ast_var_info {
	ast_reg_t alloced_reg;
	typecheck_type_t type;
	int is_global, is_readonly;
} ast_var_info_t;

typedef struct ast_id {
	uint64_t hash;

	const char* c_str;
	uint32_t length;
} ast_id_t;

typedef struct ast_array_literal {
	typecheck_type_t elem_type;

	ast_value_t* elements;
	uint32_t element_count;
} ast_array_literal_t;

typedef struct ast_value {
	typecheck_type_t type;

	enum ast_value_type {
		AST_VALUE_BOOL,
		AST_VALUE_CHAR,
		AST_VALUE_LONG,
		AST_VALUE_FLOAT,
		AST_VALUE_ALLOC_ARRAY,
		AST_VALUE_ARRAY_LITERAL,
		AST_VALUE_PROC,
		AST_VALUE_VAR,
		AST_VALUE_SET_VAR,
		AST_VALUE_SET_INDEX,
		AST_VALUE_GET_INDEX,
		AST_VALUE_SET_PROPERTY,
		AST_VALUE_GET_PROPERTY,
		AST_VALUE_BINARY_OP,
		AST_VALUE_UNARY_OP,
		AST_VALUE_PROC_CALL,
		AST_VALUE_STRUCT_LITERAL
	} value_type;

	union ast_value_data {
		int bool_flag;
		char character;
		int64_t long_int;
		double float_int;
		ast_alloc_t* alloc_array;
		ast_array_literal_t array_literal;
		ast_proc_t* procedure;
		ast_id_t variable;
		ast_set_var_t* set_var;
		ast_set_index_t* set_index;
		ast_get_index_t* get_index;
		ast_set_property_t* set_property;
		ast_get_property_t* get_property;
		ast_binary_op_t* binary_op;
		ast_unary_op_t* unary_op;
		ast_call_proc_t* proc_call;
		ast_struct_proto_t* struct_literal;
	} data;

	ast_reg_t alloced_reg;
} ast_value_t;

typedef struct ast_decl_var {
	ast_var_info_t var_info;
	ast_id_t id;
	ast_value_t set_value;
} ast_decl_var_t;

typedef struct ast_set_var {
	ast_id_t id;
	int set_global;
	ast_value_t set_value;
} set_var_t;

typedef struct ast_alloc {
	typecheck_type_t elem_type;
	ast_value_t size;
} ast_alloc_t;

typedef struct ast_set_index {
	ast_value_t array, index, value;
} ast_set_index_t;

typedef struct ast_get_index {
	ast_value_t array, index;
} ast_get_index_t;

typedef struct ast_get_property {
	ast_value_t struct_value;
	ast_id_t id;
	uint8_t index;
} ast_get_property_t;

typedef struct ast_set_property {
	ast_value_t struct_value, set_value;
	ast_id_t id;
	uint8_t index;
} ast_set_property_t;

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
	ast_reg_t output;
	int has_input, has_output;
} ast_foreign_call_t;

typedef struct ast_top_level {
	enum ast_top_level_type {
		AST_TOP_LEVEL_DECL_VAR,
		AST_TOP_LEVEL_COND,
		AST_TOP_LEVEL_VALUE,
		AST_TOP_LEVEL_RETURN_VALUE,
		AST_TOP_LEVEL_RETURN,
		AST_TOP_LEVEL_CONTINUE,
		AST_TOP_LEVEL_BREAK,
		AST_TOP_LEVEL_FOREIGN,
		AST_TOP_LEVEL_STRUCT_PROTO
	} type;

	union ast_top_level_data
	{
		ast_decl_var_t var_decl;
		ast_cond_t* conditional;
		ast_value_t value;
		ast_foreign_call_t foreign;
		ast_struct_proto_t* struct_proto;
	} data;
} ast_top_level_t;

typedef struct ast_code_block {
	ast_top_level_t* instructions;
	uint32_t instruction_count, allocated_instructions;
	uint16_t register_limit;
} ast_code_block_t;

typedef struct ast_cond {
	ast_value_t cond_val;
	int has_cond_val;

	ast_code_block_t exec_block;

	ast_cond_t* next_if_true;
	ast_cond_t* next_if_false;
} ast_cond_t;

typedef struct ast_proc {
	typecheck_type_t return_type;

	struct ast_proc_param {
		ast_id_t id;
		ast_var_info_t var_info;
	} params[TYPE_MAX_SUBTYPES - 1];

	uint8_t param_count;

	ast_code_block_t exec_block;
} ast_proc_t;

typedef struct ast_struct_proto {
	ast_id_t id;

	struct ast_struct_proto_property {
		ast_id_t id;
		typecheck_type_t type;

		ast_value_t default_value;
		int has_default_value;
	} properties[TYPE_MAX_SUBTYPES - 1];
	
	uint8_t property_count;
	typecheck_type_t type;
} ast_struct_proto_t;

typedef struct ast_var_cache_entry {
	uint64_t id_hash;
	ast_var_info_t var_info;
} ast_var_cache_entry_t;

typedef struct ast {
	struct ast_var_cache {
		ast_var_cache_entry_t entries[512], global_entries[64];
		typecheck_type_t* return_types[32];
		uint8_t pop_bounds[32], search_bounds[32], stack_top, global_entry_count, return_type_count;
		uint16_t current_entry;
	} var_cache;

	struct ast_generic_cache {
		uint64_t ids[64];
		uint8_t search_bounds[32], stack_top, decl_count;
	} generic_cache;

	struct ast_struct_cache {
		uint64_t ids[64];
		ast_struct_proto_t* proto[64];
		uint8_t definitions;
	} struct_cache;

	struct ast_include_stack {
		uint64_t visited_hashes[64];
		uint8_t visited_files;

		scanner_t scanners[32];
		uint8_t current_scanner;

		char* file_paths[32];
		char* sources[32];
	} include_stack;

	ast_code_block_t exec_block;
	uint16_t global_registers;
	error_t last_err;
} ast_t;

const int init_ast(ast_t* ast, const char* source);
void free_ast(ast_t* ast);

#endif // !AST_H