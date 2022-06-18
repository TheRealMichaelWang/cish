#pragma once

#ifndef AST_H
#define AST_H

#include <stdint.h>
#include "type.h"
#include "tokens.h"
#include "scanner.h"
#include "debug.h"
#include "postproc.h"

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
typedef struct ast_proc_typearg_transform ast_proc_typearg_t;
typedef struct ast_foreign_call ast_foreign_call_t;
typedef struct ast_record_proto ast_record_proto_t;
typedef struct ast_record_prop ast_record_prop_t;
typedef struct ast_get_prop ast_get_prop_t;
typedef struct ast_set_prop ast_set_prop_t;
typedef struct ast_type_op ast_type_op_t;
typedef struct ast_alloc_record_init_value ast_alloc_record_init_value_t;

typedef struct ast_var_info {
	uint32_t id;
	uint16_t scope_id;
	int is_global, is_readonly, has_mutated, is_used;
	typecheck_type_t type;
} ast_var_info_t;

typedef struct ast_array_literal {
	typecheck_type_t* elem_type;

	ast_value_t* elements;
	uint16_t element_count;

	postproc_trace_status_t children_trace;
} ast_array_literal_t;

typedef struct ast_alloc_record {
	ast_record_proto_t* proto;

	ast_alloc_record_init_value_t* init_values;

	uint8_t init_value_count, allocated_init_values;
	postproc_trace_status_t* typearg_traces;
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

	uint16_t id;
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
		AST_VALUE_TYPE_OP,
		AST_VALUE_PROC_CALL,
		AST_VALUE_FOREIGN
	} value_type;

	union ast_value_data {
		ast_primitive_t* primitive;
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
		ast_type_op_t* type_op;
		ast_call_proc_t* proc_call;
		ast_foreign_call_t* foreign;
	} data;

	int is_falsey, is_truey;

	uint32_t id;
	uint32_t src_loc_id;

	postproc_gc_status_t gc_status;
	postproc_trace_status_t trace_status;
	postproc_free_status_t free_status;
	int from_var, affects_state;
} ast_value_t;

typedef struct ast_decl_var {
	ast_var_info_t* var_info;
	ast_value_t set_value;
} ast_decl_var_t;

typedef struct ast_set_var {
	ast_var_info_t* var_info;
	ast_value_t set_value;

	postproc_free_status_t free_status;
} set_var_t;

typedef struct ast_alloc {
	typecheck_type_t* elem_type;
	ast_value_t size;

	postproc_trace_status_t children_trace;
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
	int is_postfix;
	token_type_t operator;
	ast_value_t operand;
} ast_unary_op;

typedef struct ast_type_op {
	token_type_t operation;
	ast_value_t operand;
	typecheck_type_t match_type;
} ast_type_op_t;

typedef struct ast_call_proc {
	ast_value_t procedure;

	postproc_trace_status_t* typearg_traces;
	typecheck_type_t* typeargs;

	ast_value_t arguments[TYPE_MAX_SUBTYPES - 1];
	uint8_t argument_count;
	uint32_t id;
} ast_call_proc_t;

typedef struct ast_foreign_call {
	ast_value_t op_id, * input;
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
		AST_STATEMENT_ABORT,
		AST_STATEMENT_RECORD_PROTO
	} type;

	union ast_statement_data
	{
		ast_decl_var_t var_decl;
		ast_cond_t* conditional;
		ast_value_t value;
		ast_record_proto_t* record_proto;
	} data;

	uint32_t src_loc_id;
} ast_statement_t;

typedef struct ast_code_block {
	ast_statement_t* instructions;
	uint32_t instruction_count, allocated_instructions;

	int affects_state;
} ast_code_block_t;

typedef struct ast_cond {
	uint16_t scope_size;
	ast_value_t* condition;

	ast_code_block_t exec_block;

	ast_cond_t* next_if_true;
	ast_cond_t* next_if_false;
} ast_cond_t;

typedef struct ast_proc {
	typecheck_type_t* return_type;
	ast_var_info_t* params;
	uint8_t param_count;
	postproc_trace_status_t* generic_arg_traces;
	uint16_t scope_size;
	ast_var_info_t* thisproc;
	ast_code_block_t exec_block;

	uint16_t id;
	int do_gc;
} ast_proc_t;

typedef struct ast_record_prop {
	uint64_t hash_id;
	uint16_t id;

	typecheck_type_t type;

	int defer_init, is_readonly;
} ast_record_prop_t;

typedef struct ast_alloc_record_init_value {
	ast_record_prop_t* property;
	ast_value_t value;

	int prop_is_static;
} ast_alloc_record_init_value_t;

typedef struct ast_record_proto {
	uint64_t hash_id;

	typecheck_type_t* base_record;
	ast_record_prop_t* properties;

	typecheck_type_t* generic_req_types;
	uint8_t generic_arguments;

	ast_alloc_record_init_value_t* default_values;

	enum ast_record_use_reqs {
		AST_RECORD_USE_ALL,
		AST_RECORD_ABSTRACT,
		AST_RECORD_FINAL
	} use_reqs;

	uint8_t id, property_count, allocated_properties;
	uint16_t index_offset, default_value_count, child_record_count;

	int typeargs_defined, fully_defined, do_gc, linked;
} ast_record_proto_t;

typedef struct ast_get_prop {
	ast_value_t record;
	ast_record_prop_t* property;
} ast_get_prop_t;

typedef struct ast_set_prop {
	ast_value_t record, value;
	ast_record_prop_t* property;
} ast_set_prop_t;

typedef struct ast_var_cache_entry {
	uint64_t id_hash;
	ast_var_info_t* var_info;
} ast_var_cache_entry_t;

typedef struct ast_generic_cache_entry {
	uint64_t id_hash, gen_id;
	typecheck_type_t* req_type;
} ast_generic_cache_entry_t;

typedef struct ast {
	ast_code_block_t exec_block;

	ast_record_proto_t** record_protos;
	uint8_t record_count, allocated_records;

	ast_primitive_t** primitives;
	uint16_t constant_count, allocated_constants, proc_count;

	dbg_table_t* dbg_table;

	uint32_t value_count, var_decl_count, proc_call_count;
} ast_t;

typedef struct ast_parser_frame ast_parser_frame_t;

typedef struct ast_parser_frame {
	ast_var_cache_entry_t* locals;
	typecheck_type_t* return_type;

	ast_generic_cache_entry_t* generics;

	uint16_t local_count, allocated_locals, scoped_locals, max_scoped_locals;
	uint8_t generic_count, generic_id_count;

	ast_parser_frame_t* parent_frame;
} ast_parser_frame_t;

typedef struct ast_parser {
	ast_parser_frame_t frames[32];
	uint8_t current_frame;

	ast_var_cache_entry_t* globals;
	uint16_t global_count, allocated_globals, top_level_local_count;

	ast_t* ast;
	multi_scanner_t multi_scanner;

	postproc_gc_status_t* top_level_global_gc_stats;
	postproc_gc_status_t* global_gc_stats;
	int* shared_globals;

	safe_gc_t* safe_gc;

	error_t last_err;
} ast_parser_t;

int ast_record_sub_prop_type(ast_parser_t* ast_parser, typecheck_type_t record_type, uint64_t id, typecheck_type_t* out_type);

int init_ast_parser(ast_parser_t* ast_parser, safe_gc_t* safe_gc, const char* source);
void free_ast_parser(ast_parser_t* ast_parser);

int init_ast(ast_t* ast, ast_parser_t* ast_parser, dbg_table_t* dbg_table);

#endif // !AST_H