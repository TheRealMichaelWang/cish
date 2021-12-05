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
typedef struct ast_foreign_call ast_foreign_call_t;
typedef struct ast_record_proto ast_record_proto_t;
typedef struct ast_record_prop ast_record_prop_t;
typedef struct ast_get_prop ast_get_prop_t;
typedef struct ast_set_prop ast_set_prop_t;

typedef enum ast_gc_status {
	GC_NONE,
	GC_EXTERN_ALLOC,
	GC_LOCAL_ALLOC
} ast_gc_status_t;

typedef struct ast_var_info {
	uint32_t id;
	int is_global, is_readonly, has_mutated;
	typecheck_type_t type;
	ast_gc_status_t gc_status;
} ast_var_info_t;

typedef struct ast_array_literal {
	typecheck_type_t* elem_type;

	ast_value_t* elements;
	uint16_t element_count;
} ast_array_literal_t;

typedef struct ast_alloc_record {
	ast_record_proto_t* proto;
	struct ast_alloc_record_init_value {
		ast_record_prop_t* property;
		ast_value_t* value;
	}* init_values;
	uint8_t init_value_count;
} ast_alloc_record_t;

typedef struct ast_primitive {
	enum ast_primitive_type {
		AST_PRIMITIVE_BOOL,
		AST_PRIMITIVE_CHAR,
		AST_PRIMITIVE_LONG,
		AST_PRIMITIVE_FLOAT
	} type;

	union ast_primitive_data
	{
		int bool_flag;
		char character;
		int64_t long_int;
		double float_int;
	} data;
} ast_primitive_t;

typedef struct ast_value {
	typecheck_type_t type;

	enum ast_value_type {
		AST_VALUE_PRIMITIVE,
		AST_VALUE_ALLOC_ARRAY,
		AST_VALUE_ALLOC_RECORD,
		AST_VALUE_ARRAY_LITERAL,
		AST_VALUE_PROC,
		AST_VALUE_VAR,
		AST_VALUE_SET_VAR,
		AST_VALUE_SET_INDEX,
		AST_VALUE_SET_PROP,
		AST_VALUE_GET_INDEX,
		AST_VALUE_GET_PROP,
		AST_VALUE_BINARY_OP,
		AST_VALUE_UNARY_OP,
		AST_VALUE_PROC_CALL,
		AST_VALUE_FOREIGN
	} value_type;

	union ast_value_data {
		ast_primitive_t primitive;
		ast_alloc_t* alloc_array;
		ast_alloc_record_t alloc_record;
		ast_array_literal_t array_literal;
		ast_proc_t* procedure;
		ast_var_info_t* variable;
		ast_set_var_t* set_var;
		ast_set_index_t* set_index;
		ast_set_prop_t* set_prop;
		ast_get_index_t* get_index;
		ast_get_prop_t* get_prop;
		ast_binary_op_t* binary_op;
		ast_unary_op_t* unary_op;
		ast_call_proc_t* proc_call;
		ast_foreign_call_t* foreign;
	} data;

	uint32_t id;
	ast_gc_status_t gc_status;
} ast_value_t;

typedef struct ast_decl_var {
	ast_var_info_t* var_info;
	ast_value_t set_value;
} ast_decl_var_t;

typedef struct ast_set_var {
	ast_var_info_t* var_info;
	ast_value_t set_value;
	int gc_trace;
} set_var_t;

typedef struct ast_alloc {
	typecheck_type_t* elem_type;
	ast_value_t size;
} ast_alloc_t;

typedef struct ast_set_index {
	ast_value_t array, index, value;
	int gc_trace;
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
	uint32_t id;
} ast_call_proc_t;

typedef struct ast_foreign_call {
	ast_value_t op_id, *input;
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
		AST_STATEMENT_RECORD_PROTO
	} type;

	union ast_statement_data
	{
		ast_decl_var_t var_decl;
		ast_cond_t* conditional;
		ast_value_t value;
		ast_record_proto_t* record_proto;
	} data;
} ast_statement_t;

typedef struct ast_code_block {
	ast_statement_t* instructions;
	uint32_t instruction_count, allocated_instructions;
} ast_code_block_t;

typedef struct ast_cond {
	ast_value_t* condition;

	ast_code_block_t exec_block;

	ast_cond_t* next_if_true;
	ast_cond_t* next_if_false;
} ast_cond_t;

typedef struct ast_proc_param {
	ast_var_info_t var_info;
	uint16_t id;
} ast_proc_param_t;

typedef struct ast_proc {
	typecheck_type_t* return_type;

	ast_proc_param_t *params;
	uint8_t param_count;
	ast_var_info_t* thisproc;

	ast_code_block_t exec_block;

	int do_gc;
} ast_proc_t;

typedef struct ast_record_prop {
	uint64_t hash_id;
	uint16_t id;

	typecheck_type_t type;

	ast_value_t* default_value;
} ast_record_prop_t;

typedef struct ast_record_proto {
	uint64_t hash_id;

	typecheck_type_t* base_record;

	ast_record_prop_t* properties;
	uint8_t generic_arguments;

	uint8_t property_count, allocated_properties;
	uint16_t id, index_offset;
	int defined, do_gc;
} ast_record_proto_t;

typedef struct ast_get_prop {
	ast_value_t record;
	ast_record_prop_t* property;
} ast_get_prop_t;

typedef struct ast_set_prop {
	ast_value_t record, value;
	ast_record_prop_t* property;
	int gc_trace;
} ast_set_prop_t;

typedef struct ast_var_cache_entry {
	uint64_t id_hash;
	ast_var_info_t* var_info;
} ast_var_cache_entry_t;

typedef struct ast {
	ast_code_block_t exec_block;

	ast_record_proto_t** record_protos;
	uint8_t record_count, allocated_records;

	uint32_t value_count, proc_call_count;
	uint16_t total_var_decls, total_constants;
} ast_t;

typedef struct ast_parser_frame ast_parser_frame_t;

typedef struct ast_parser_frame {
	ast_var_cache_entry_t* locals;
	typecheck_type_t* return_type;

	uint64_t* generics;

	uint16_t local_count, allocated_locals;
	uint8_t generic_count;

	ast_parser_frame_t* parent_frame;

	int do_gc;
} ast_parser_frame_t;

typedef struct ast_parser {
	ast_parser_frame_t frames[32];
	uint8_t current_frame;

	ast_var_cache_entry_t* globals;
	uint16_t global_count, allocated_globals;

	ast_t* ast;
	multi_scanner_t multi_scanner;

	error_t last_err;
} ast_parser_t;

int init_ast_parser(ast_parser_t* ast_parser, const char* source);
void free_ast_parser(ast_parser_t* ast_parser);

int init_ast(ast_t* ast, ast_parser_t* ast_parser);
void free_ast(ast_t* ast);

#endif // !AST_H