#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "error.h"
#include "postproc.h"
#include "ast.h"

#define LAST_TOK ast_parser->multi_scanner.last_tok
#define CURRENT_FRAME ast_parser->frames[ast_parser->current_frame - 1]

#define MATCH_TOK(TYPE) {if(LAST_TOK.type != TYPE) PANIC(ast_parser, ERROR_UNEXPECTED_TOK)}
#define READ_TOK PANIC_ON_FAIL(multi_scanner_scan_tok(&ast_parser->multi_scanner), ast_parser, ast_parser->multi_scanner.last_err);

#ifdef _DEBUG
int santize_type_comp(ast_parser_t* ast_parser, typecheck_type_t* a, typecheck_type_t b) {
	if (!typecheck_compatible(ast_parser, a, b))
		return 0;
	return 1;
}
#define TYPE_COMP(A, B) santize_type_comp(ast_parser, A, B)
#else
#define TYPE_COMP(A, B) typecheck_compatible(ast_parser, A, B)
#endif

#define TYPE_COPY(DEST, SRC) PANIC_ON_FAIL(copy_typecheck_type(ast_parser->safe_gc, DEST, SRC), ast_parser, ERROR_MEMORY)

static int parse_value(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type);
static int parse_expression(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type, int expect_auto, int min_prec);

static int parse_type(ast_parser_t* ast_parser, typecheck_type_t* type, int allow_auto, int allow_nothing);
static int parse_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, int encapsulated, int in_loop);

static ast_statement_t* ast_code_block_append(ast_parser_t* ast_parser, ast_code_block_t* code_block) {
	if (code_block->instruction_count == code_block->allocated_instructions) {
		ast_statement_t* new_ins = safe_realloc(ast_parser->safe_gc, code_block->instructions, (code_block->allocated_instructions += 64) * sizeof(ast_statement_t));
		PANIC_ON_FAIL(new_ins, ast_parser, ERROR_MEMORY);
		code_block->instructions = new_ins;
	}
	return &code_block->instructions[code_block->instruction_count++];
}

static int ast_parser_new_frame(ast_parser_t* ast_parser, typecheck_type_t* return_type, int access_previous) {
	if (ast_parser->current_frame == 32)
		PANIC(ast_parser, ERROR_INTERNAL);
	ast_parser_frame_t* next_frame = &ast_parser->frames[ast_parser->current_frame++];
	PANIC_ON_FAIL(next_frame->locals = safe_malloc(ast_parser->safe_gc, (next_frame->allocated_locals = 8) * sizeof(ast_var_cache_entry_t)), ast_parser, ERROR_MEMORY);
	next_frame->local_count = 0;
	if (access_previous) {
		next_frame->parent_frame = &ast_parser->frames[ast_parser->current_frame - 2];
		next_frame->return_type = next_frame->parent_frame->return_type;
		next_frame->scoped_locals = next_frame->parent_frame->scoped_locals;
		next_frame->max_scoped_locals = next_frame->parent_frame->max_scoped_locals;
	}
	else {
		PANIC_ON_FAIL(next_frame->generics = safe_malloc(ast_parser->safe_gc, TYPE_MAX_SUBTYPES * sizeof(uint64_t)), ast_parser, ERROR_MEMORY);
		next_frame->scoped_locals = 0;
		next_frame->max_scoped_locals = 0;
		next_frame->return_type = return_type;
		next_frame->parent_frame = NULL;
		next_frame->generic_count = 0;
		next_frame->generic_id_count = 0;
	}
	return 1;
}

static int ast_parser_close_frame(ast_parser_t* ast_parser) {
	PANIC_ON_FAIL(ast_parser->current_frame, ast_parser, ERROR_INTERNAL);
	ast_parser_frame_t* free_frame = &ast_parser->frames[--ast_parser->current_frame];
	if (!free_frame->parent_frame)
		safe_free(ast_parser->safe_gc, free_frame->generics);
	else if (free_frame->max_scoped_locals > free_frame->parent_frame->max_scoped_locals)
		free_frame->parent_frame->max_scoped_locals = free_frame->max_scoped_locals;
	safe_free(ast_parser->safe_gc, free_frame->locals);
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

static int ast_parser_decl_var(ast_parser_t* ast_parser, uint64_t id, ast_var_info_t* var_info) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	if (ast_parser_find_var(ast_parser, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	var_info->is_used = 0;
	if (var_info->is_global) {
		if (ast_parser->global_count == ast_parser->allocated_globals) {
			ast_var_cache_entry_t* new_globals = safe_realloc(ast_parser->safe_gc, ast_parser->globals, (ast_parser->allocated_globals += 64) * sizeof(ast_var_cache_entry_t));
			PANIC_ON_FAIL(new_globals, ast_parser, ERROR_MEMORY);
			ast_parser->globals = new_globals;
		}
		var_info->id = ast_parser->ast->var_decl_count++;
		var_info->scope_id = ast_parser->global_count;
		ast_parser->globals[ast_parser->global_count++] = (ast_var_cache_entry_t){
			.id_hash = id,
			.var_info = var_info
		};
	}
	else {
		if (current_frame->local_count == current_frame->allocated_locals) {
			ast_var_cache_entry_t* new_locals = safe_realloc(ast_parser->safe_gc, current_frame->locals, (current_frame->allocated_locals += 64) * sizeof(ast_var_cache_entry_t));
			PANIC_ON_FAIL(new_locals, ast_parser, ERROR_MEMORY);
			current_frame->locals = new_locals;
		}
		var_info->id = ast_parser->ast->var_decl_count++;

		current_frame->locals[current_frame->local_count++] = (ast_var_cache_entry_t){
			.id_hash = id,
			.var_info = var_info
		};

		var_info->scope_id = current_frame->scoped_locals++;
		if (current_frame->scoped_locals > current_frame->max_scoped_locals)
			current_frame->max_scoped_locals = current_frame->scoped_locals;
	}
	return 1;
}

static ast_generic_cache_entry_t* ast_parser_find_generic(ast_parser_t* ast_parser, uint64_t id) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	while (current_frame->parent_frame)
		current_frame = current_frame->parent_frame;
	for (uint_fast8_t i = 0; i < current_frame->generic_count; i++)
		if (current_frame->generics[i].id_hash == id)
			return &current_frame->generics[i];
	return NULL;
}

static int ast_parser_decl_generic(ast_parser_t* ast_parser, uint64_t id, typecheck_type_t* req_type) {
	ast_parser_frame_t* current_frame = &ast_parser->frames[ast_parser->current_frame - 1];
	if (ast_parser_find_generic(ast_parser, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	if (req_type && req_type->type == TYPE_TYPEARG)
		PANIC(ast_parser, ERROR_UNEXPECTED_TYPE);

	while (current_frame->parent_frame)
		current_frame = current_frame->parent_frame;
	if (current_frame->generic_count == TYPE_MAX_SUBTYPES)
		PANIC(ast_parser, ERROR_MEMORY);

	current_frame->generics[current_frame->generic_count++] = (ast_generic_cache_entry_t){
		.id_hash = id,
		.gen_id = current_frame->generic_id_count++,
		.req_type = req_type,
	};
	return 1;
}

static ast_record_proto_t* ast_parser_find_record_proto(ast_parser_t* ast_parser, uint64_t id) {
	for (uint_fast8_t i = 0; i < ast_parser->ast->record_count; i++)
		if (ast_parser->ast->record_protos[i]->hash_id == id)
			return ast_parser->ast->record_protos[i];
	return NULL;
}

static ast_record_proto_t* ast_parser_decl_record(ast_parser_t* ast_parser, uint64_t id) {
	if (ast_parser_find_record_proto(ast_parser, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	if (ast_parser->ast->record_count == UINT8_MAX)
		PANIC(ast_parser, ERROR_INTERNAL);
	if (ast_parser->ast->record_count == ast_parser->ast->allocated_records) {
		ast_record_proto_t** new_records = safe_realloc(ast_parser->safe_gc, ast_parser->ast->record_protos, (ast_parser->ast->allocated_records += 2) * sizeof(ast_record_proto_t*));
		PANIC_ON_FAIL(new_records, ast_parser, ERROR_MEMORY);
		ast_parser->ast->record_protos = new_records;
	}
	ast_record_proto_t* new_rec = safe_malloc(ast_parser->safe_gc, sizeof(ast_record_proto_t));
	PANIC_ON_FAIL(new_rec, ast_parser, ERROR_MEMORY);
	new_rec->hash_id = id;
	new_rec->id = ast_parser->ast->record_count;
	new_rec->base_record = NULL;
	PANIC_ON_FAIL(new_rec->properties = safe_malloc(ast_parser->safe_gc, (new_rec->allocated_properties = 4) * sizeof(ast_record_prop_t)), ast_parser, ERROR_MEMORY);
	new_rec->property_count = 0;
	new_rec->typeargs_defined = 0;
	new_rec->fully_defined = 0;
	new_rec->index_offset = 0;
	new_rec->child_record_count = 0;
	new_rec->linked = 0;
	ast_parser->ast->record_protos[ast_parser->ast->record_count++] = new_rec;
	return new_rec;
}

static ast_record_prop_t* ast_record_find_prop(ast_parser_t* ast_parser, ast_record_proto_t* record, uint64_t id) {
	if (!record->fully_defined)
		return NULL;
	for (uint_fast8_t i = 0; i < record->property_count; i++)
		if (record->properties[i].hash_id == id)
			return &record->properties[i];
	if (record->base_record)
		return ast_record_find_prop(ast_parser, ast_parser->ast->record_protos[record->base_record->type_id], id);
	return NULL;
}

int ast_record_sub_prop_type(ast_parser_t* ast_parser, typecheck_type_t record_type, uint64_t id, typecheck_type_t* out_type) {
	PANIC_ON_FAIL(record_type.type == TYPE_SUPER_RECORD, ast_parser, ERROR_UNEXPECTED_TYPE);

	ast_record_proto_t* record = ast_parser->ast->record_protos[record_type.type_id];

	PANIC_ON_FAIL(record->fully_defined, ast_parser, ERROR_UNDECLARED);
	PANIC_ON_FAIL(record_type.sub_type_count == record->generic_arguments, ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);

	for (uint_fast8_t i = 0; i < record->property_count; i++)
		if (record->properties[i].hash_id == id) {
			TYPE_COPY(out_type, record->properties[i].type);
			PANIC_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, record_type.sub_types, out_type), ast_parser, ERROR_MEMORY);
			return 1;
		}
	if (record->base_record) {
		ESCAPE_ON_FAIL(ast_record_sub_prop_type(ast_parser, *record->base_record, id, out_type));
		PANIC_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, record_type.sub_types, out_type), ast_parser, ERROR_MEMORY);
		return 1;
	}

	PANIC(ast_parser, ERROR_UNDECLARED);
}

static int code_paths_return(ast_code_block_t code_block, int is_while_true, int* cannot_return) {
	for (uint_fast32_t i = 0; i < code_block.instruction_count; i++)
		switch (code_block.instructions[i].type)
		{
		case AST_STATEMENT_BREAK:
			if (is_while_true) {
				*cannot_return = 1;
				return 0;
			}
			break;
		case AST_STATEMENT_RETURN:
		case AST_STATEMENT_RETURN_VALUE:
		case AST_STATEMENT_ABORT:
			return 1;
		case AST_STATEMENT_COND: {
			ast_cond_t* cond = code_block.instructions[i].data.conditional;
			if (cond->next_if_true) { //cond is a while loop
				int cant_ret_flag = 0;
				if (cond->condition->is_truey && code_paths_return(cond->exec_block, 1, &cant_ret_flag) && !cant_ret_flag)
					return 1;
			}
			else { //cond is an if else chain
				ast_cond_t* last_cond = NULL;
				int temp_cant_ret = 0;
				for (; cond; cond = cond->next_if_false) {
					if (!code_paths_return(cond->exec_block, is_while_true, &temp_cant_ret))
						goto escape_cond_path;
					last_cond = cond;
				}
				if (!last_cond->condition) //an else has been detected
					return 1;
			escape_cond_path:
				if (is_while_true && temp_cant_ret) {
					*cannot_return = 1;
					return 0;
				}
			}
			break;
		}
		}
	return is_while_true;
}

static int substitute_value_types(ast_parser_t* ast_parser, ast_value_t input_val, typecheck_type_t* input_typeargs, ast_value_t* output_val) {
	*output_val = input_val;
	TYPE_COPY(&output_val->type, input_val.type);
	ESCAPE_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, input_typeargs, &output_val->type));

	switch (output_val->value_type)
	{
	case AST_VALUE_ALLOC_ARRAY:
		output_val->data.alloc_array->elem_type = output_val->type.sub_types;
		break;
	case AST_VALUE_ARRAY_LITERAL:
		output_val->data.array_literal.elem_type = output_val->type.sub_types;
		PANIC_ON_FAIL(output_val->data.array_literal.elements = safe_malloc(ast_parser->safe_gc, input_val.data.array_literal.element_count * sizeof(ast_value_t)), ast_parser, ERROR_MEMORY);
		for (uint_fast16_t i = 0; i < input_val.data.array_literal.element_count; i++)
			ESCAPE_ON_FAIL(substitute_value_types(ast_parser, input_val.data.array_literal.elements[i], input_typeargs, &output_val->data.array_literal.elements[i]));
		break;
	case AST_VALUE_ALLOC_RECORD:
		PANIC_ON_FAIL(output_val->data.alloc_record.init_values = safe_malloc(ast_parser->safe_gc, input_val.data.alloc_record.init_value_count * sizeof(ast_alloc_record_init_value_t)), ast_parser, ERROR_MEMORY);
		for (uint_fast16_t i = 0; i < input_val.data.alloc_record.init_value_count; i++) {
			output_val->data.alloc_record.init_values[i] = input_val.data.alloc_record.init_values[i];
			ESCAPE_ON_FAIL(substitute_value_types(ast_parser, input_val.data.alloc_record.init_values[i].value, input_typeargs, &output_val->data.alloc_record.init_values[i].value));
		}
		break;
	case AST_VALUE_PROC_CALL:
		PANIC_ON_FAIL(output_val->data.proc_call = safe_malloc(ast_parser->safe_gc, sizeof(ast_call_proc_t)), ast_parser, ERROR_MEMORY);
		*output_val->data.proc_call = *input_val.data.proc_call;
		PANIC_ON_FAIL(output_val->data.proc_call->typeargs = safe_malloc(ast_parser->safe_gc, input_val.data.proc_call->procedure.type.type_id * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);

		for (uint_fast8_t i = 0; i < input_val.data.proc_call->procedure.type.type_id; i++) {
			TYPE_COPY(&output_val->data.proc_call->typeargs[i], input_val.data.proc_call->typeargs[i]);
			ESCAPE_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, input_typeargs, &output_val->data.proc_call->typeargs[i]));
		}
		for (uint_fast8_t i = 0; i < input_val.data.proc_call->argument_count; i++)
			ESCAPE_ON_FAIL(substitute_value_types(ast_parser, input_val.data.proc_call->arguments[i], input_typeargs, &output_val->data.proc_call->arguments[i]));
		break;
	}
	return 1;
}

static ast_record_prop_t* ast_record_decl_prop(ast_parser_t* ast_parser, ast_record_proto_t* record, uint64_t id) {
	if (record->fully_defined)
		PANIC(ast_parser, ERROR_READONLY);
	if (ast_record_find_prop(ast_parser, record, id))
		PANIC(ast_parser, ERROR_REDECLARATION);
	if (record->property_count == 255)
		PANIC(ast_parser, ERROR_INTERNAL);
	if (record->property_count == record->allocated_properties) {
		record->allocated_properties *= 2;
		ast_record_prop_t* new_props = safe_realloc(ast_parser->safe_gc, record->properties, record->allocated_properties * sizeof(ast_record_prop_t));
		PANIC_ON_FAIL(new_props, ast_parser, ERROR_MEMORY);
		record->properties = new_props;
	}
	ast_record_prop_t* next_prop = &record->properties[record->property_count];
	next_prop->hash_id = id;
	next_prop->id = record->property_count++;
	return next_prop;
}

int init_ast_parser(ast_parser_t* ast_parser, safe_gc_t* safe_gc, const char* source) {
	PANIC_ON_FAIL(ast_parser->globals = safe_malloc(safe_gc, (ast_parser->allocated_globals = 16) * sizeof(ast_var_cache_entry_t)), ast_parser, ERROR_MEMORY);
	ast_parser->current_frame = 0;
	ast_parser->last_err = ERROR_NONE;
	ast_parser->global_count = 0;
	ast_parser->safe_gc = safe_gc;
	PANIC_ON_FAIL(init_multi_scanner(&ast_parser->multi_scanner, safe_gc, source), ast_parser, ast_parser->multi_scanner.last_err);
	return 1;
}

void free_ast_parser(ast_parser_t* ast_parser) {
	while (ast_parser->current_frame)
		ast_parser_close_frame(ast_parser);
}

static int parse_subtypes(ast_parser_t* ast_parser, typecheck_type_t* super_type, typecheck_type_t* req_types, int8_t expected_subtypes) {
	MATCH_TOK(TOK_LESS);
	typecheck_type_t sub_types[TYPE_MAX_SUBTYPES];
	super_type->sub_type_count = 0;

	int gen_args_set_flag = 0;
	do {
		READ_TOK;
		if (super_type->sub_type_count == TYPE_MAX_SUBTYPES)
			PANIC(ast_parser, ERROR_MEMORY);
		if (LAST_TOK.type == TOK_DIVIDE) {
			PANIC_ON_FAIL(super_type->type == TYPE_SUPER_PROC && !gen_args_set_flag, ast_parser, ERROR_UNEXPECTED_TOK);
			super_type->type_id = super_type->sub_type_count;
			gen_args_set_flag = 1;
		}
		else {
			ESCAPE_ON_FAIL(parse_type(ast_parser, &sub_types[super_type->sub_type_count], 0, super_type->type == TYPE_SUPER_PROC && super_type->sub_type_count == 0));
			if (req_types)
				PANIC_ON_FAIL(TYPE_COMP(&sub_types[super_type->sub_type_count], req_types[super_type->sub_type_count]), ast_parser, ERROR_UNEXPECTED_TYPE);
			super_type->sub_type_count++;
		}
	} while (LAST_TOK.type == TOK_COMMA);
	MATCH_TOK(TOK_MORE);
	READ_TOK;
	if (expected_subtypes != -1 && super_type->sub_type_count != expected_subtypes)
		PANIC(ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);
	if (super_type->sub_type_count) {
		PANIC_ON_FAIL(super_type->sub_types = safe_malloc(ast_parser->safe_gc, super_type->sub_type_count * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		memcpy(super_type->sub_types, sub_types, super_type->sub_type_count * sizeof(typecheck_type_t));
	}
	return 1;
}

static int parse_type(ast_parser_t* ast_parser, typecheck_type_t* type, int allow_auto, int allow_nothing) {
	if (LAST_TOK.type >= TOK_TYPECHECK_BOOL && LAST_TOK.type <= TOK_TYPECHECK_ARRAY) {
		type->type = TYPE_PRIMITIVE_BOOL + (LAST_TOK.type - TOK_TYPECHECK_BOOL);
		type->type_id = 0;
	}
	else if (LAST_TOK.type >= TOK_AUTO && LAST_TOK.type <= TOK_TYPECHECK_ANY) {
		PANIC_ON_FAIL((LAST_TOK.type == TOK_AUTO) ? allow_auto : ((LAST_TOK.type == TOK_NOTHING) ? allow_nothing : 1), ast_parser, ERROR_TYPE_NOT_ALLOWED);
		type->type = LAST_TOK.type - TOK_AUTO + TYPE_AUTO;
	}
	else if (LAST_TOK.type == TOK_IDENTIFIER) {
		uint64_t hash_id = hash_s(LAST_TOK.str, LAST_TOK.length);
		READ_TOK;
		ast_generic_cache_entry_t* generic_type = ast_parser_find_generic(ast_parser, hash_id);
		if (generic_type) {
			type->type = TYPE_TYPEARG;
			type->type_id = generic_type->gen_id;
		}
		else {
			ast_record_proto_t* proto = ast_parser_find_record_proto(ast_parser, hash_id);
			type->type = TYPE_SUPER_RECORD;
			if (proto) {
				type->type_id = proto->id;
				if (!proto->generic_arguments) {
					type->sub_type_count = 0;
					return 1;
				}
				if (proto->typeargs_defined)
					ESCAPE_ON_FAIL(parse_subtypes(ast_parser, type, proto->generic_req_types, proto->generic_arguments))
				else {
					ESCAPE_ON_FAIL(parse_subtypes(ast_parser, type, NULL, proto->generic_arguments));
					for (uint_fast8_t i = 0; i < type->sub_type_count; i++) {
						typecheck_type_t lowest_common_type_req;
						PANIC_ON_FAIL(typecheck_lowest_common_type(ast_parser, type->sub_types[i], proto->generic_req_types[i], &lowest_common_type_req), ast_parser, ERROR_MEMORY);
						free_typecheck_type(ast_parser->safe_gc, &proto->generic_req_types[i]);
						proto->generic_req_types[i] = lowest_common_type_req;
					}
				}
			}
			else {
				ESCAPE_ON_FAIL(proto = ast_parser_decl_record(ast_parser, hash_id));
				type->type_id = proto->id;
				if (LAST_TOK.type == TOK_LESS) {
					ESCAPE_ON_FAIL(parse_subtypes(ast_parser, type, NULL, -1));
					PANIC_ON_FAIL(proto->generic_req_types = safe_malloc(ast_parser->safe_gc, type->sub_type_count * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
					for (uint_fast8_t i = 0; i < type->sub_type_count; i++)
						TYPE_COPY(&proto->generic_req_types[i], type->sub_types[i]);
				}
				else {
					type->sub_type_count = 0;
					//proto->generic_req_types = NULL;
				}
				proto->generic_arguments = type->sub_type_count;
			}
		}
		return 1;
	}
	else
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	READ_TOK;
	if (HAS_SUBTYPES(*type))
		ESCAPE_ON_FAIL(parse_subtypes(ast_parser, type, NULL, type->type == TYPE_SUPER_ARRAY ? 1 : -1));
	return 1;
}

static int parse_type_params(ast_parser_t* ast_parser, typecheck_type_t* req_types, uint8_t* decled_type_params, uint8_t existing_params, int8_t expected_params) {
	*decled_type_params = 0;

	MATCH_TOK(TOK_LESS);
	while (LAST_TOK.type != TOK_MORE) {
		if (*decled_type_params + existing_params == TYPE_MAX_SUBTYPES)
			PANIC(ast_parser, ERROR_INTERNAL);
		if (expected_params != -1 && *decled_type_params == expected_params)
			PANIC(ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);
		READ_TOK;
		MATCH_TOK(TOK_IDENTIFIER);
		uint64_t id = hash_s(LAST_TOK.str, LAST_TOK.length);

		READ_TOK;
		if (LAST_TOK.type == TOK_EXTEND && req_types) {
			READ_TOK;
			ESCAPE_ON_FAIL(parse_type(ast_parser, &req_types[*decled_type_params], 0, 0));

			ESCAPE_ON_FAIL(ast_parser_decl_generic(ast_parser, id, &req_types[*decled_type_params]));
		}
		else {
			req_types[*decled_type_params].type = TYPE_ANY;
			ESCAPE_ON_FAIL(ast_parser_decl_generic(ast_parser, id, NULL));
		}

		(*decled_type_params)++;
		if (LAST_TOK.type != TOK_COMMA)
			MATCH_TOK(TOK_MORE);
	}
	if (expected_params != -1 && *decled_type_params != expected_params)
		PANIC(ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);
	READ_TOK;
	return 1;
}

static int prim_value_comp(ast_primitive_t a, ast_primitive_t b) {
	if (a.type != b.type)
		return 0;
	switch (a.type)
	{
	case AST_PRIMITIVE_BOOL:
		return a.data.bool_flag == b.data.bool_flag;
	case AST_PRIMITIVE_CHAR:
		return a.data.character == b.data.character;
	case AST_PRIMITIVE_LONG:
		return a.data.long_int == b.data.long_int;
	case AST_PRIMITIVE_FLOAT:
		return a.data.float_int == b.data.float_int;
	}
}

static ast_primitive_t* ast_add_prim_value(ast_parser_t* ast_parser, ast_primitive_t primitive) {
	for (uint_fast16_t i = 0; i < ast_parser->ast->constant_count; i++)
		if (prim_value_comp(*ast_parser->ast->primitives[i], primitive))
			return ast_parser->ast->primitives[i];
	if (ast_parser->ast->constant_count == ast_parser->ast->allocated_constants) {
		ast_primitive_t** new_primitives = safe_realloc(ast_parser->safe_gc, ast_parser->ast->primitives, (ast_parser->ast->allocated_constants += 5) * sizeof(ast_primitive_t*));
		PANIC_ON_FAIL(new_primitives, ast_parser, ERROR_MEMORY);
		ast_parser->ast->primitives = new_primitives;
	}
	ast_primitive_t* prim_buf = safe_malloc(ast_parser->safe_gc, sizeof(ast_primitive_t));
	PANIC_ON_FAIL(prim_buf, ast_parser, ERROR_MEMORY);
	*prim_buf = primitive;
	prim_buf->id = ast_parser->ast->constant_count;
	ast_parser->ast->primitives[ast_parser->ast->constant_count++] = prim_buf;
	return prim_buf;
}

static ast_primitive_t* parse_prim_value(ast_parser_t* ast_parser) {
	ast_primitive_t primitive;
	switch (LAST_TOK.type)
	{
	case TOK_NUMERICAL:
		primitive.type = AST_PRIMITIVE_LONG;
		for (uint_fast32_t i = 0; i < LAST_TOK.length; i++) {
			if (LAST_TOK.str[i] == '.')
				primitive.type = AST_PRIMITIVE_FLOAT;
			if (LAST_TOK.str[i] == 'f') { //parse as float
				primitive.data.float_int = strtod(LAST_TOK.str, NULL);
				primitive.type = AST_PRIMITIVE_FLOAT;
				goto end_parse_num;
			}
			else if (LAST_TOK.str[i] == 'h') { //parse hexadecimal
				primitive.data.long_int = strtol(LAST_TOK.str, NULL, 16);
				goto end_parse_num;
			}
		}
		if (primitive.type == AST_PRIMITIVE_LONG)
			primitive.data.long_int = strtol(LAST_TOK.str, NULL, 10);
		else
			primitive.data.float_int = strtod(LAST_TOK.str, NULL);
	end_parse_num:
		break;
	case TOK_CHAR: {
		primitive.type = AST_PRIMITIVE_CHAR;
		scanner_t scanner;
		init_scanner(&scanner, LAST_TOK.str, LAST_TOK.length);
		PANIC_ON_FAIL(scanner_scan_char(&scanner), ast_parser, scanner.last_err);
		primitive.data.character = scanner.last_char;
		break;
	}
	case TOK_TRUE:
	case TOK_FALSE:
		primitive.type = AST_PRIMITIVE_BOOL;
		primitive.data.bool_flag = LAST_TOK.type - TOK_FALSE;
		break;
	default:
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	};
	READ_TOK;
	return ast_add_prim_value(ast_parser, primitive);
}

static int parse_var_decl(ast_parser_t* ast_parser, ast_decl_var_t* ast_decl_var) {
	PANIC_ON_FAIL(ast_decl_var->var_info = safe_malloc(ast_parser->safe_gc, sizeof(ast_var_info_t)), ast_parser, ERROR_MEMORY);
	ast_decl_var->var_info->is_global = 0;
	ast_decl_var->var_info->is_readonly = 0;
	while (LAST_TOK.type == TOK_GLOBAL || LAST_TOK.type == TOK_READONLY) {
		if (LAST_TOK.type == TOK_GLOBAL) {
			PANIC_ON_FAIL(!CURRENT_FRAME.return_type, ast_parser, ERROR_INTERNAL);
			ast_decl_var->var_info->is_global = 1;
		}
		else if (LAST_TOK.type == TOK_READONLY)
			ast_decl_var->var_info->is_readonly = 1;
		READ_TOK;
	}
	ESCAPE_ON_FAIL(parse_type(ast_parser, &ast_decl_var->var_info->type, 1, 0));
	MATCH_TOK(TOK_IDENTIFIER);

	uint64_t id = hash_s(LAST_TOK.str, LAST_TOK.length);
	READ_TOK;
	ESCAPE_ON_FAIL(ast_parser_decl_var(ast_parser, id, ast_decl_var->var_info));
	MATCH_TOK(TOK_SET);
	READ_TOK;
	ESCAPE_ON_FAIL(parse_expression(ast_parser, &ast_decl_var->set_value, &ast_decl_var->var_info->type, 0, 0));
	return 1;
}

static int parse_condition(ast_parser_t* ast_parser, ast_cond_t* conditional, int enforce_encapsulate) {
	if (enforce_encapsulate) {
		MATCH_TOK(TOK_OPEN_PAREN);
		READ_TOK;
	}
	PANIC_ON_FAIL(conditional->condition = safe_malloc(ast_parser->safe_gc, sizeof(ast_value_t)), ast_parser, ERROR_MEMORY);
	ESCAPE_ON_FAIL(parse_expression(ast_parser, conditional->condition, &typecheck_bool, 0, 0));
	if (enforce_encapsulate) {
		MATCH_TOK(TOK_CLOSE_PAREN);
		READ_TOK;
	}
	return 1;
}

static int parse_if_else(ast_parser_t* ast_parser, ast_cond_t* conditional, int in_loop) {
	MATCH_TOK(TOK_IF);
	READ_TOK;
	ESCAPE_ON_FAIL(parse_condition(ast_parser, conditional, 1));
	ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 1));
	ESCAPE_ON_FAIL(parse_code_block(ast_parser, &conditional->exec_block, 1, in_loop));
	conditional->scope_size = CURRENT_FRAME.scoped_locals;
	ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
	if (LAST_TOK.type == TOK_ELSE) {
		READ_TOK;
		PANIC_ON_FAIL(conditional->next_if_false = safe_malloc(ast_parser->safe_gc, sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);
		if (LAST_TOK.type == TOK_IF)
			ESCAPE_ON_FAIL(parse_if_else(ast_parser, conditional->next_if_false, in_loop))
		else {
			conditional->next_if_false->condition = NULL;
			conditional->next_if_false->next_if_false = NULL;
			ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 1));
			ESCAPE_ON_FAIL(parse_code_block(ast_parser, &conditional->next_if_false->exec_block, 1, in_loop));
			conditional->next_if_false->scope_size = CURRENT_FRAME.scoped_locals;
			ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
		}
	}
	else
		conditional->next_if_false = NULL;
	conditional->next_if_true = NULL;
	return 1;
}

static int parse_statment(ast_parser_t* ast_parser, ast_statement_t* statement, ast_code_block_t* code_block, int in_loop) {
	PANIC_ON_FAIL(debug_table_add_loc(ast_parser->ast->dbg_table, ast_parser->multi_scanner, &statement->src_loc_id), ast_parser, ERROR_MEMORY);
	
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
	ast_var_decl:
		statement->type = AST_STATEMENT_DECL_VAR;
		ESCAPE_ON_FAIL(parse_var_decl(ast_parser, &statement->data.var_decl));
		break;
	case TOK_IF:
		statement->type = AST_STATEMENT_COND;
		PANIC_ON_FAIL(statement->data.conditional = safe_malloc(ast_parser->safe_gc, sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);
		ESCAPE_ON_FAIL(parse_if_else(ast_parser, statement->data.conditional, in_loop));
		goto no_check_semicolon;
	case TOK_WHILE:
		READ_TOK;
		statement->type = AST_STATEMENT_COND;
		PANIC_ON_FAIL(statement->data.conditional = safe_malloc(ast_parser->safe_gc, sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);

		ESCAPE_ON_FAIL(parse_condition(ast_parser, statement->data.conditional, 1));
		ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 1));
		ESCAPE_ON_FAIL(parse_code_block(ast_parser, &statement->data.conditional->exec_block, 1, 1));
		statement->data.conditional->scope_size = CURRENT_FRAME.scoped_locals;
		ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
		statement->data.conditional->next_if_true = statement->data.conditional;
		statement->data.conditional->next_if_false = NULL;
		goto no_check_semicolon;
	case TOK_FOR: {
		PANIC_ON_FAIL(code_block, ast_parser, ERROR_UNEXPECTED_TOK);

		READ_TOK;
		MATCH_TOK(TOK_OPEN_PAREN);
		READ_TOK;

		statement->type = AST_STATEMENT_COND;
		PANIC_ON_FAIL(statement->data.conditional = safe_malloc(ast_parser->safe_gc, sizeof(ast_cond_t)), ast_parser, ERROR_MEMORY);
		ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 1));

		ast_statement_t* init_statement = ast_code_block_append(ast_parser, code_block);
		ESCAPE_ON_FAIL(init_statement);
		ESCAPE_ON_FAIL(parse_statment(ast_parser, init_statement, code_block, in_loop));
		ESCAPE_ON_FAIL(parse_condition(ast_parser, statement->data.conditional, 0));
		MATCH_TOK(TOK_SEMICOLON);
		READ_TOK;

		ast_statement_t next_statment;
		parse_statment(ast_parser, &next_statment, NULL, in_loop);
		MATCH_TOK(TOK_CLOSE_PAREN);
		READ_TOK;

		ESCAPE_ON_FAIL(parse_code_block(ast_parser, &statement->data.conditional->exec_block, 1, 1));
		statement->data.conditional->scope_size = CURRENT_FRAME.scoped_locals;
		ast_statement_t* added_statement = ast_code_block_append(ast_parser, &statement->data.conditional->exec_block);
		ESCAPE_ON_FAIL(added_statement);
		*added_statement = next_statment;
		ast_parser_close_frame(ast_parser);

		statement->data.conditional->next_if_true = statement->data.conditional;
		statement->data.conditional->next_if_false = NULL;
		goto no_check_semicolon;
	}
	case TOK_FOREIGN:
		goto statment_value;
	case TOK_IDENTIFIER: {
		if (ast_parser_find_var(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length))) {
		statment_value:
			statement->type = AST_STATEMENT_VALUE;
			typecheck_type_t type = { .type = TYPE_AUTO };
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &statement->data.value, &type, 1, 0));
			if (statement->data.value.value_type == AST_VALUE_UNARY_OP)
				statement->data.value.data.unary_op->is_postfix = 0;
			free_typecheck_type(ast_parser->safe_gc, &type);
		}
		else
			goto ast_var_decl;
		break;
	}
	case TOK_CONTINUE:
	case TOK_BREAK:
		PANIC_ON_FAIL(in_loop, ast_parser, ERROR_CANNOT_CONTINUE + LAST_TOK.type - TOK_CONTINUE);
	case TOK_ABORT:
		statement->type = AST_STATEMENT_CONTINUE + LAST_TOK.type - TOK_CONTINUE;
		READ_TOK;
		break;
	case TOK_RETURN:
		READ_TOK;
		if (LAST_TOK.type == TOK_SEMICOLON) {
			statement->type = AST_STATEMENT_RETURN;
			PANIC_ON_FAIL(TYPE_COMP(CURRENT_FRAME.return_type, typecheck_nothing), ast_parser, ERROR_UNEXPECTED_TYPE);
		}
		else {
			statement->type = AST_STATEMENT_RETURN_VALUE;
			PANIC_ON_FAIL(CURRENT_FRAME.return_type, ast_parser, ERROR_CANNOT_RETURN);
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &statement->data.value, CURRENT_FRAME.return_type, 0, 0));
		}
		break;
	case TOK_INCLUDE: {
		READ_TOK;
		MATCH_TOK(TOK_STRING);
		char* file_source = safe_malloc(ast_parser->safe_gc, (LAST_TOK.length + 1) * sizeof(char));
		PANIC_ON_FAIL(file_source, ast_parser, ERROR_MEMORY);
		memcpy(file_source, LAST_TOK.str, LAST_TOK.length * sizeof(char));
		file_source[LAST_TOK.length] = 0;
		READ_TOK;
		PANIC_ON_FAIL(multi_scanner_visit(&ast_parser->multi_scanner, file_source), ast_parser, ast_parser->multi_scanner.last_err);
		safe_free(ast_parser->safe_gc, file_source);

		MATCH_TOK(TOK_SEMICOLON);
		READ_TOK;

		return parse_statment(ast_parser, statement, code_block, in_loop);
	}
	{
		enum ast_record_use_reqs use_req;
	case TOK_FINAL:
		use_req = AST_RECORD_FINAL;
		READ_TOK;
		goto begin_parse_record;
	case TOK_ABSTRACT:
		use_req = AST_RECORD_ABSTRACT;
		READ_TOK;
		goto begin_parse_record;
	case TOK_RECORD:
		use_req = AST_RECORD_USE_ALL;
	begin_parse_record:
		MATCH_TOK(TOK_RECORD);

		PANIC_ON_FAIL(!CURRENT_FRAME.return_type, ast_parser, ERROR_UNEXPECTED_TOK);
		READ_TOK;
		MATCH_TOK(TOK_IDENTIFIER);
		uint64_t hash_id = hash_s(LAST_TOK.str, LAST_TOK.length);
		READ_TOK;

		ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 0));
		ast_record_proto_t* record_proto = ast_parser_find_record_proto(ast_parser, hash_id);

		if (record_proto) {
			if (record_proto->fully_defined)
				PANIC(ast_parser, ERROR_REDECLARATION);
			if (record_proto->generic_arguments) {
				typecheck_type_t* req_types = safe_malloc(ast_parser->safe_gc, record_proto->generic_arguments * sizeof(typecheck_type_t));
				PANIC_ON_FAIL(req_types, ast_parser, ERROR_MEMORY);
				uint8_t decled_type_params;
				ESCAPE_ON_FAIL(parse_type_params(ast_parser, req_types, &decled_type_params, 0, record_proto->generic_arguments));
				for (uint_fast8_t i = 0; i < record_proto->generic_arguments; i++) {
					if (typecheck_has_type(req_types[i], TYPE_TYPEARG) || !TYPE_COMP(&record_proto->generic_req_types[i], req_types[i]))
						PANIC(ast_parser, ERROR_UNEXPECTED_TYPE);
					free_typecheck_type(ast_parser->safe_gc, &record_proto->generic_req_types[i]);
				}
				safe_free(ast_parser->safe_gc, record_proto->generic_req_types);
				record_proto->generic_req_types = req_types;
			}
			if (use_req == AST_RECORD_FINAL)
				PANIC_ON_FAIL(record_proto->child_record_count == 0, ast_parser, ERROR_CANNOT_EXTEND);
		}
		else {
			ESCAPE_ON_FAIL(record_proto = ast_parser_decl_record(ast_parser, hash_id));
			if (LAST_TOK.type == TOK_LESS) {
				PANIC_ON_FAIL(record_proto->generic_req_types = safe_malloc(ast_parser->safe_gc, TYPE_MAX_SUBTYPES * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
				ESCAPE_ON_FAIL(parse_type_params(ast_parser, record_proto->generic_req_types, &record_proto->generic_arguments, 0, -1));
			}
			else
				record_proto->generic_arguments = 0;
		}
		record_proto->use_reqs = use_req;
		record_proto->typeargs_defined = 1;

		if (LAST_TOK.type == TOK_EXTEND) {
			READ_TOK;
			PANIC_ON_FAIL(record_proto->base_record = safe_malloc(ast_parser->safe_gc, sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
			ESCAPE_ON_FAIL(parse_type(ast_parser, record_proto->base_record, 0, 0));
			PANIC_ON_FAIL(record_proto->base_record->type == TYPE_SUPER_RECORD, ast_parser, ERROR_UNEXPECTED_TYPE);

			ast_record_proto_t* base_record = ast_parser->ast->record_protos[record_proto->base_record->type_id];

			for (ast_record_proto_t* check_type = base_record; check_type->base_record; check_type = ast_parser->ast->record_protos[check_type->base_record->type_id]) {
				if (check_type == record_proto)
					PANIC(ast_parser, ERROR_INTERNAL); //pls no recursive types
			}

			if (base_record->fully_defined)
				PANIC_ON_FAIL(base_record->use_reqs != AST_RECORD_FINAL, ast_parser, ERROR_CANNOT_EXTEND)
			else
				base_record->child_record_count++;
		}

		record_proto->default_value_count = 0;

		if (LAST_TOK.type == TOK_OPEN_BRACE) {
			READ_TOK;
			uint16_t allocated_defaults = 5;
			PANIC_ON_FAIL(record_proto->default_values = safe_malloc(ast_parser->safe_gc, allocated_defaults * sizeof(ast_alloc_record_init_value_t)), ast_parser, ERROR_MEMORY);
			do {
				ast_record_prop_t* prop;
				int defer_init = 0;
				int is_readonly = 0;

				for (;;)
				{
					if (LAST_TOK.type == TOK_READONLY) {
						PANIC_ON_FAIL(!is_readonly, ast_parser, ERROR_UNEXPECTED_TOK);
						is_readonly = 1;
						READ_TOK;
					}
					else if (LAST_TOK.type == TOK_DEFERINIT) {
						PANIC_ON_FAIL(!defer_init, ast_parser, ERROR_UNEXPECTED_TOK);
						defer_init = 1;
						READ_TOK;
					}
					else if (defer_init || is_readonly)
						goto decl_prop;
					else break;
				}
				if (LAST_TOK.type == TOK_IDENTIFIER && record_proto->base_record) {
					prop = ast_record_find_prop(ast_parser, ast_parser->ast->record_protos[record_proto->base_record->type_id], hash_s(LAST_TOK.str, LAST_TOK.length));
					if (prop == NULL)
						goto decl_prop;
					READ_TOK;
					MATCH_TOK(TOK_SET);
				}
				else decl_prop: {
					typecheck_type_t prop_type;
					ESCAPE_ON_FAIL(parse_type(ast_parser, &prop_type, 1, 0));
					MATCH_TOK(TOK_IDENTIFIER);
					ESCAPE_ON_FAIL(prop = ast_record_decl_prop(ast_parser, record_proto, hash_s(LAST_TOK.str, LAST_TOK.length)));

					prop->type = prop_type;
					prop->defer_init = defer_init;
					prop->is_readonly = is_readonly;
					READ_TOK;

					if (LAST_TOK.type != TOK_SET)
						goto end_parse_prop;
				}

				READ_TOK;
				if (record_proto->default_value_count == allocated_defaults) {
					ast_alloc_record_init_value_t* new_defaults = safe_realloc(ast_parser->safe_gc, record_proto->default_values, (allocated_defaults += 3) * sizeof(ast_alloc_record_init_value_t));
					PANIC_ON_FAIL(new_defaults, ast_parser, ERROR_MEMORY);
					record_proto->default_values = new_defaults;
				}

				//ESCAPE_ON_FAIL(ast_postproc_link_record(ast_parser, record_proto, NULL))
				record_proto->default_values[record_proto->default_value_count].property = prop;
				if (prop >= record_proto->properties && prop < (record_proto->properties + record_proto->property_count))
					ESCAPE_ON_FAIL(parse_expression(ast_parser, &record_proto->default_values[record_proto->default_value_count].value, &prop->type, 0, 0))
				else {
					typecheck_type_t real_prop_type;
					ESCAPE_ON_FAIL(ast_record_sub_prop_type(ast_parser, *record_proto->base_record, prop->hash_id, &real_prop_type));
					ESCAPE_ON_FAIL(parse_expression(ast_parser, &record_proto->default_values[record_proto->default_value_count].value, &real_prop_type, 0, 0));
					free_typecheck_type(ast_parser->safe_gc, &real_prop_type);
				}

				record_proto->default_values[record_proto->default_value_count].prop_is_static = !(prop >= record_proto->properties && prop < (record_proto->properties + record_proto->property_count));
				if (record_proto->default_values[record_proto->default_value_count].prop_is_static)
					record_proto->default_values[record_proto->default_value_count].property = prop; //a static property doesn't need special pointer magic
				else
					record_proto->default_values[record_proto->default_value_count].property = (void*)(uint64_t)(prop - record_proto->properties); //we need to do this because record_proto->properties may get realloced
				record_proto->default_value_count++;

			end_parse_prop:
				MATCH_TOK(TOK_SEMICOLON);
				READ_TOK;
			} while (LAST_TOK.type != TOK_CLOSE_BRACE);

			//messy pointer aritmetic - this "relinks" properties together because a property pointer may not be constant since the properties list gets realloced.
			for (uint_fast16_t i = 0; i < record_proto->default_value_count; i++) {
				if (!record_proto->default_values[i].prop_is_static) {
					record_proto->default_values[i].property = &record_proto->properties[(uint64_t)record_proto->default_values[i].property];
					record_proto->default_values[i].prop_is_static = 1;
				}
			}
			READ_TOK;
		}
		else {
			record_proto->default_values = NULL;
			MATCH_TOK(TOK_SEMICOLON);
			READ_TOK;
		}

		statement->type = AST_STATEMENT_RECORD_PROTO;
		statement->data.record_proto = record_proto;
		ast_parser_close_frame(ast_parser);
		record_proto->fully_defined = 1;
		goto no_check_semicolon;
	}
	default:
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	}

	MATCH_TOK(TOK_SEMICOLON);
	READ_TOK;
no_check_semicolon:;
	return 1;
}

static int parse_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, int is_not_top_lvl, int in_loop) {
	PANIC_ON_FAIL(code_block->instructions = safe_malloc(ast_parser->safe_gc, (code_block->allocated_instructions = 16) * sizeof(ast_statement_t)), ast_parser, ERROR_MEMORY);
	code_block->instruction_count = 0;
	if (is_not_top_lvl) {
		if (LAST_TOK.type != TOK_OPEN_BRACE) {
			ast_statement_t state_buf;
			ESCAPE_ON_FAIL(parse_statment(ast_parser, &state_buf, code_block, in_loop));
			ast_statement_t* statement = ast_code_block_append(ast_parser, code_block);
			ESCAPE_ON_FAIL(statement);
			*statement = state_buf;
			return 1;
		}
		else
			READ_TOK;
	}
	do {
		ast_statement_t state_buf;
		ESCAPE_ON_FAIL(parse_statment(ast_parser, &state_buf, code_block, in_loop));
		ast_statement_t* statement = ast_code_block_append(ast_parser, code_block);
		ESCAPE_ON_FAIL(statement);
		*statement = state_buf;
	} while (is_not_top_lvl ? LAST_TOK.type != TOK_CLOSE_BRACE : LAST_TOK.type != TOK_EOF);
	READ_TOK;
	return 1;
}

static int parse_value(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type) {
	value->is_falsey = value->is_truey = 0;
	PANIC_ON_FAIL(debug_table_add_loc(ast_parser->ast->dbg_table, ast_parser->multi_scanner, &value->src_loc_id), ast_parser, ERROR_MEMORY);
	uint32_t src_loc_id = value->src_loc_id;

	switch (LAST_TOK.type) {
	case TOK_TRUE:
	case TOK_FALSE:
		value->is_truey = LAST_TOK.type == TOK_TRUE;
		value->is_falsey = LAST_TOK.type == TOK_FALSE;
	case TOK_NUMERICAL:
	case TOK_CHAR:
		ESCAPE_ON_FAIL(value->data.primitive = parse_prim_value(ast_parser));
		value->value_type = AST_VALUE_PRIMITIVE;
		value->type.type = TYPE_PRIMITIVE_BOOL + value->data.primitive->type - AST_PRIMITIVE_BOOL;
		break;
	case TOK_STRING: {
		char* buffer = safe_malloc(ast_parser->safe_gc, LAST_TOK.length * sizeof(char));
		PANIC_ON_FAIL(buffer, ast_parser, ERROR_MEMORY);
		value->data.array_literal.element_count = 0;
		scanner_t str_scanner;
		init_scanner(&str_scanner, LAST_TOK.str, LAST_TOK.length);
		scanner_scan_char(&str_scanner);
		while (str_scanner.last_char) {
			buffer[value->data.array_literal.element_count++] = str_scanner.last_char;
			scanner_scan_char(&str_scanner);
		}
		value->value_type = AST_VALUE_ARRAY_LITERAL;
		value->type.type = TYPE_SUPER_ARRAY;

		PANIC_ON_FAIL(value->type.sub_types = safe_malloc(ast_parser->safe_gc, sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		value->type.sub_types->type = TYPE_PRIMITIVE_CHAR;
		value->type.sub_type_count = 1;
		value->data.array_literal.elem_type = value->type.sub_types;
		PANIC_ON_FAIL(value->data.array_literal.elements = safe_malloc(ast_parser->safe_gc, value->data.array_literal.element_count * sizeof(ast_value_t)), ast_parser, ERROR_MEMORY)
			for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++) {
				ESCAPE_ON_FAIL(value->data.array_literal.elements[i].data.primitive = ast_add_prim_value(ast_parser, (ast_primitive_t) {
					.data.character = buffer[i],
					.type = AST_PRIMITIVE_CHAR
				}));
				value->data.array_literal.elements[i].value_type = AST_VALUE_PRIMITIVE;
				value->data.array_literal.elements[i].type.type = TYPE_PRIMITIVE_CHAR;
				value->data.array_literal.elements[i].is_falsey = value->data.array_literal.elements[i].is_truey = 0;
				value->data.array_literal.elements[i].src_loc_id = src_loc_id;
				value->data.array_literal.elements[i].id = ast_parser->ast->value_count++;
			}
		safe_free(ast_parser->safe_gc, buffer);
		READ_TOK;
		break;
	}
	case TOK_OPEN_BRACKET: {
		value->value_type = AST_VALUE_ARRAY_LITERAL;
		value->type.type = TYPE_SUPER_ARRAY;
		PANIC_ON_FAIL(value->type.sub_types = safe_malloc(ast_parser->safe_gc, sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
		value->type.sub_types->type = TYPE_AUTO;
		value->type.sub_type_count = 1;
		value->data.array_literal.elem_type = value->type.sub_types;

		uint32_t alloc_elems = 8;
		value->data.array_literal.element_count = 0;
		PANIC_ON_FAIL(value->data.array_literal.elements = safe_malloc(ast_parser->safe_gc, alloc_elems * sizeof(ast_value_t)), ast_parser, ERROR_MEMORY);

		READ_TOK;
		while (LAST_TOK.type != TOK_CLOSE_BRACKET) {
			if (value->data.array_literal.element_count == alloc_elems) {
				ast_value_t* new_elems = safe_realloc(ast_parser->safe_gc, value->data.array_literal.elements, (alloc_elems += 64) * sizeof(ast_value_t));
				PANIC_ON_FAIL(new_elems, ast_parser, ERROR_MEMORY);
				value->data.array_literal.elements = new_elems;
			}
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.array_literal.elements[value->data.array_literal.element_count++], value->type.sub_types, 0, 0));
			if (LAST_TOK.type != TOK_CLOSE_BRACKET) {
				MATCH_TOK(TOK_COMMA);
				READ_TOK;
			}
		}
		READ_TOK;
		break;
	}
	case TOK_NEW: {
		typecheck_type_t type_alloc_buf;
		READ_TOK;
		ESCAPE_ON_FAIL(parse_type(ast_parser, &type_alloc_buf, 0, 0));
		if (LAST_TOK.type == TOK_OPEN_BRACKET) {
			value->value_type = AST_VALUE_ALLOC_ARRAY;
			value->type.type = TYPE_SUPER_ARRAY;
			value->type.sub_type_count = 1;
			PANIC_ON_FAIL(value->type.sub_types = safe_malloc(ast_parser->safe_gc, sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);
			PANIC_ON_FAIL(value->data.alloc_array = safe_malloc(ast_parser->safe_gc, sizeof(ast_alloc_t)), ast_parser, ERROR_MEMORY);
			value->value_type = AST_VALUE_ALLOC_ARRAY;
			value->data.alloc_array->elem_type = value->type.sub_types;
			*value->data.alloc_array->elem_type = type_alloc_buf;
			READ_TOK;
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.alloc_array->size, &typecheck_int, 0, 0));
			MATCH_TOK(TOK_CLOSE_BRACKET);
			READ_TOK;
		}
		else {
#define CHECK_INIT_PROP_LENS if (value->data.alloc_record.init_value_count == value->data.alloc_record.allocated_init_values) { \
								ast_alloc_record_init_value_t* new_init_values = safe_realloc(ast_parser->safe_gc, value->data.alloc_record.init_values, (value->data.alloc_record.allocated_init_values += 3) * sizeof(ast_alloc_record_init_value_t)); \
								PANIC_ON_FAIL(new_init_values, ast_parser, ERROR_MEMORY); \
								value->data.alloc_record.init_values = new_init_values; \
							}


			PANIC_ON_FAIL(type_alloc_buf.type == TYPE_SUPER_RECORD, ast_parser, ERROR_UNEXPECTED_TYPE);
			value->value_type = AST_VALUE_ALLOC_RECORD;
			ast_record_proto_t* current_proto = value->data.alloc_record.proto = ast_parser->ast->record_protos[type_alloc_buf.type_id];
			ESCAPE_ON_FAIL(ast_postproc_link_record(ast_parser, current_proto, NULL));

			int* overriden_defaults = safe_calloc(ast_parser->safe_gc, current_proto->property_count + current_proto->index_offset, sizeof(int));
			PANIC_ON_FAIL(overriden_defaults, ast_parser, ERROR_MEMORY);
			value->data.alloc_record.init_value_count = 0;
			value->data.alloc_record.allocated_init_values = 0;
			value->type = type_alloc_buf;

			PANIC_ON_FAIL(value->data.alloc_record.init_values = safe_malloc(ast_parser->safe_gc, (value->data.alloc_record.allocated_init_values = 5) * sizeof(ast_alloc_record_init_value_t)), ast_parser, ERROR_MEMORY);
			if (LAST_TOK.type == TOK_OPEN_BRACE) {
				PANIC_ON_FAIL(current_proto->fully_defined, ast_parser, ERROR_UNDECLARED);
				PANIC_ON_FAIL(current_proto->use_reqs != AST_RECORD_ABSTRACT, ast_parser, ERROR_CANNOT_INIT);
				READ_TOK;
				do {
					MATCH_TOK(TOK_IDENTIFIER);
					uint64_t prop_id = hash_s(LAST_TOK.str, LAST_TOK.length);

					CHECK_INIT_PROP_LENS;
					PANIC_ON_FAIL(value->data.alloc_record.init_values[value->data.alloc_record.init_value_count].property = ast_record_find_prop(ast_parser, current_proto, prop_id), ast_parser, ERROR_UNDECLARED);
					READ_TOK;
					MATCH_TOK(TOK_SET);
					READ_TOK;
					typecheck_type_t prop_expected_type;

					ESCAPE_ON_FAIL(ast_record_sub_prop_type(ast_parser, value->type, prop_id, &prop_expected_type));
					ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.alloc_record.init_values[value->data.alloc_record.init_value_count].value, &prop_expected_type, 0, 0));

					overriden_defaults[value->data.alloc_record.init_values[value->data.alloc_record.init_value_count].property->id] = 1;
					value->data.alloc_record.init_value_count++;
					free_typecheck_type(ast_parser->safe_gc, &prop_expected_type);
					MATCH_TOK(TOK_SEMICOLON);
					READ_TOK;
				} while (LAST_TOK.type != TOK_CLOSE_BRACE);
				READ_TOK;
			}

			typecheck_type_t current_type;
			TYPE_COPY(&current_type, value->type);

			for (; current_proto; current_proto = ast_parser->ast->record_protos[current_type.type_id]) {
				for (uint_fast16_t i = 0; i < current_proto->default_value_count; i++) {
					if (!overriden_defaults[current_proto->default_values[i].property->id]) {
						CHECK_INIT_PROP_LENS;
						value->data.alloc_record.init_values[value->data.alloc_record.init_value_count] = current_proto->default_values[i];

						//TYPE_COPY(&value->data.alloc_record.init_values[value->data.alloc_record.init_value_count].value.type,  current_proto->default_values[i].value.type);
						//ESCAPE_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, current_type.sub_types,  &value->data.alloc_record.init_values[value->data.alloc_record.init_value_count].value.type));

						ESCAPE_ON_FAIL(substitute_value_types(ast_parser, current_proto->default_values[i].value, current_type.sub_types, &value->data.alloc_record.init_values[value->data.alloc_record.init_value_count].value));

						overriden_defaults[current_proto->default_values[i].property->id] = 1;
						value->data.alloc_record.init_value_count++;
					}
				}
				for (uint_fast8_t i = 0; i < current_proto->property_count; i++) {
					if (!current_proto->properties[i].defer_init)
						PANIC_ON_FAIL(overriden_defaults[current_proto->properties[i].id], ast_parser, ERROR_READ_UNINIT);
				}
				if (current_proto->base_record) {
					typecheck_type_t next;
					TYPE_COPY(&next, *current_proto->base_record);
					ESCAPE_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, current_type.sub_types, &next));
					current_type = *current_proto->base_record;
				}
				else break;
			}
			safe_free(ast_parser->safe_gc, overriden_defaults);
#undef CHECK_INIT_PROP_LENS
		}
		break;
	}
	case TOK_IDENTIFIER: {
		ast_var_info_t* var_info = ast_parser_find_var(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length));
		PANIC_ON_FAIL(var_info, ast_parser, ERROR_UNDECLARED);

		READ_TOK;
		if (LAST_TOK.type == TOK_SET) {
			READ_TOK;
			if (var_info->is_readonly)
				PANIC(ast_parser, ERROR_READONLY);
			value->value_type = AST_VALUE_SET_VAR;
			PANIC_ON_FAIL(value->data.set_var = safe_malloc(ast_parser->safe_gc, sizeof(ast_set_var_t)), ast_parser, ERROR_MEMORY);
			value->data.set_var->var_info = var_info;
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.set_var->set_value, &var_info->type, 0, 0));
			TYPE_COPY(&value->type, value->data.set_var->set_value.type);
		}
		else {
			value->value_type = AST_VALUE_VAR;
			value->data.variable = var_info;
			TYPE_COPY(&value->type, var_info->type);
		}
		break;
	}
	case TOK_OPEN_PAREN:
		READ_TOK;
		ESCAPE_ON_FAIL(parse_expression(ast_parser, value, type, 0, 0));
		MATCH_TOK(TOK_CLOSE_PAREN);
		READ_TOK;
		break;
	case TOK_NOT:
	case TOK_HASHTAG:
	case TOK_SUBTRACT:
	case TOK_INCREMENT:
	case TOK_DECREMENT: {
		value->value_type = AST_VALUE_UNARY_OP;
		PANIC_ON_FAIL(value->data.unary_op = safe_malloc(ast_parser->safe_gc, sizeof(ast_unary_op_t)), ast_parser, ERROR_MEMORY);
		value->data.unary_op->operator = LAST_TOK.type;
		value->data.unary_op->is_postfix = 0;

		typecheck_type_t array_typecheck = typecheck_array;
		array_typecheck.sub_types = safe_malloc(ast_parser->safe_gc, sizeof(typecheck_type_t));
		array_typecheck.sub_types->type = TYPE_AUTO;
		array_typecheck.sub_type_count = 1;
		READ_TOK;
		ESCAPE_ON_FAIL(parse_value(ast_parser, &value->data.unary_op->operand, value->data.unary_op->operator == TOK_HASHTAG ? &array_typecheck : type));

		if (((value->data.unary_op->operator == TOK_SUBTRACT || value->data.unary_op->operator == TOK_INCREMENT || value->data.unary_op->operator == TOK_DECREMENT) && !TYPE_COMP(type, typecheck_int) && !TYPE_COMP(type, typecheck_float)) ||
			(value->data.unary_op->operator == TOK_HASHTAG && !TYPE_COMP(type, typecheck_int)) ||
			(value->data.unary_op->operator == TOK_NOT && !TYPE_COMP(type, typecheck_bool)))
			PANIC(ast_parser, ERROR_UNEXPECTED_TYPE);
		if (value->data.unary_op->operator == TOK_INCREMENT || value->data.unary_op->operator == TOK_DECREMENT)
			PANIC_ON_FAIL(value->data.unary_op->operand.value_type == AST_VALUE_VAR || value->data.unary_op->operand.value_type == AST_VALUE_SET_VAR, ast_parser, ERROR_UNEXPECTED_TOK);

		free_typecheck_type(ast_parser->safe_gc, &array_typecheck);
		break;
	}
	case TOK_DYNAMIC_CAST: {
		READ_TOK;
		MATCH_TOK(TOK_LESS);
		READ_TOK;

		PANIC_ON_FAIL(value->data.type_op = safe_malloc(ast_parser->safe_gc, sizeof(ast_type_op_t)), ast_parser, ERROR_MEMORY);
		value->data.type_op->operation = TOK_DYNAMIC_CAST;
		value->value_type = AST_VALUE_TYPE_OP;

		ESCAPE_ON_FAIL(parse_type(ast_parser, &value->data.type_op->match_type, 0, 0));
		if (typecheck_has_type(value->data.type_op->match_type, TYPE_TYPEARG))
			PANIC_ON_FAIL(CURRENT_FRAME.return_type, ast_parser, ERROR_UNEXPECTED_TYPE);
		PANIC_ON_FAIL(value->data.type_op->match_type.type == TYPE_SUPER_RECORD || value->data.type_op->match_type.type == TYPE_TYPEARG, ast_parser, ERROR_UNEXPECTED_TYPE);

		TYPE_COPY(&value->type, value->data.type_op->match_type);

		MATCH_TOK(TOK_MORE);
		READ_TOK;
		MATCH_TOK(TOK_OPEN_PAREN);
		READ_TOK;

		typecheck_type_t op_type = { .type = TYPE_AUTO };
		ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.type_op->operand, &op_type, 0, 0));
		PANIC_ON_FAIL(op_type.type == TYPE_SUPER_RECORD || op_type.type == TYPE_TYPEARG, ast_parser, ERROR_UNEXPECTED_TYPE);
		free_typecheck_type(ast_parser->safe_gc, &op_type);

		MATCH_TOK(TOK_CLOSE_PAREN);
		READ_TOK;
		break;
	}
	case TOK_TYPECHECK_PROC: {
		READ_TOK;
		value->value_type = AST_VALUE_PROC;
		ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 0));

		typecheck_type_t generic_type_reqs[TYPE_MAX_SUBTYPES];
		if (LAST_TOK.type == TOK_LESS)
			ESCAPE_ON_FAIL(parse_type_params(ast_parser, generic_type_reqs, &value->type.type_id, 1, -1))
		else
			value->type.type_id = 0;

		typecheck_type_t argument_unmodded_types[TYPE_MAX_SUBTYPES];

		PANIC_ON_FAIL(value->data.procedure = safe_malloc(ast_parser->safe_gc, sizeof(ast_proc_t)), ast_parser, ERROR_MEMORY);
		PANIC_ON_FAIL(value->data.procedure->params = safe_malloc(ast_parser->safe_gc, (TYPE_MAX_SUBTYPES - (1 + value->type.type_id)) * sizeof(ast_var_info_t)), ast_parser, ERROR_MEMORY);
		value->data.procedure->param_count = 0;
		MATCH_TOK(TOK_OPEN_PAREN);
		READ_TOK;
		while (LAST_TOK.type != TOK_CLOSE_PAREN)
		{
			if (value->data.procedure->param_count == TYPE_MAX_SUBTYPES - (1 + value->type.type_id))
				PANIC(ast_parser, ERROR_INTERNAL);
			value->data.procedure->params[value->data.procedure->param_count] = (ast_var_info_t){
				.is_global = 0,
				.is_readonly = 1,
			};

			ESCAPE_ON_FAIL(parse_type(ast_parser, &argument_unmodded_types[value->data.procedure->param_count], 0, 0));
			TYPE_COPY(&value->data.procedure->params[value->data.procedure->param_count].type, argument_unmodded_types[value->data.procedure->param_count]);

			MATCH_TOK(TOK_IDENTIFIER);
			ESCAPE_ON_FAIL(ast_parser_decl_var(ast_parser, hash_s(LAST_TOK.str, LAST_TOK.length), &value->data.procedure->params[value->data.procedure->param_count]));
			value->data.procedure->param_count++;
			READ_TOK;
			if (LAST_TOK.type != TOK_COMMA)
				MATCH_TOK(TOK_CLOSE_PAREN)
			else
				READ_TOK;
		}
		value->type.type = TYPE_SUPER_PROC;
		PANIC_ON_FAIL(value->type.sub_types = safe_malloc(ast_parser->safe_gc, (value->type.sub_type_count = value->data.procedure->param_count + 1 + value->type.type_id) * sizeof(typecheck_type_t)), ast_parser, ERROR_MEMORY);

		memcpy(value->type.sub_types, generic_type_reqs, value->type.type_id * sizeof(typecheck_type_t));
		memcpy(&value->type.sub_types[value->type.type_id + 1], argument_unmodded_types, value->data.procedure->param_count * sizeof(typecheck_type_t));

		READ_TOK;

		if (LAST_TOK.type == TOK_RETURN) {
			READ_TOK;
			ESCAPE_ON_FAIL(parse_type(ast_parser, &value->type.sub_types[value->type.type_id], 1, 1));
		}
		else
			value->type.sub_types[value->type.type_id].type = TYPE_AUTO;

		CURRENT_FRAME.return_type = value->data.procedure->return_type = &value->type.sub_types[value->type.type_id];

		PANIC_ON_FAIL(value->data.procedure->thisproc = safe_malloc(ast_parser->safe_gc, sizeof(ast_var_info_t)), ast_parser, ERROR_MEMORY);
		*value->data.procedure->thisproc = (ast_var_info_t){
			.is_global = 0,
			.is_readonly = 1,
			.type = value->type,
		};
		ESCAPE_ON_FAIL(ast_parser_decl_var(ast_parser, 7572967076558961, value->data.procedure->thisproc));

		if (LAST_TOK.type == TOK_LAMBDA_RETURN) {
			READ_TOK;
			value->data.procedure->exec_block.instruction_count = 0;
			PANIC_ON_FAIL(value->data.procedure->exec_block.instructions = safe_malloc(ast_parser->safe_gc, (value->data.procedure->exec_block.allocated_instructions = 1) * sizeof(ast_statement_t)), ast_parser, ERROR_MEMORY);
			ast_statement_t* return_statement = ast_code_block_append(ast_parser, &value->data.procedure->exec_block);
			ESCAPE_ON_FAIL(return_statement);
			return_statement->type = AST_STATEMENT_RETURN_VALUE;
			ESCAPE_ON_FAIL(parse_expression(ast_parser, &return_statement->data.value, CURRENT_FRAME.return_type, CURRENT_FRAME.return_type->type != TYPE_AUTO, 0));
			uint32_t src_loc_id = return_statement->src_loc_id = return_statement->data.value.src_loc_id;
			if (return_statement->data.value.type.type == TYPE_NOTHING) {
				return_statement->type = AST_STATEMENT_VALUE;
				ESCAPE_ON_FAIL(return_statement = ast_code_block_append(ast_parser, &value->data.procedure->exec_block));
				return_statement->src_loc_id = src_loc_id;
				return_statement->type = AST_STATEMENT_RETURN;
			}
		}
		else
			ESCAPE_ON_FAIL(parse_code_block(ast_parser, &value->data.procedure->exec_block, 1, 0));

		value->data.procedure->scope_size = CURRENT_FRAME.max_scoped_locals;
		value->data.procedure->id = ast_parser->ast->proc_count++;
		if (value->data.procedure->return_type->type == TYPE_AUTO)
			value->data.procedure->return_type->type = TYPE_NOTHING;

		if (!code_paths_return(value->data.procedure->exec_block, 0, NULL)) {
			if (value->data.procedure->return_type->type == TYPE_NOTHING) { //add implicit return
				ast_statement_t* return_statement = ast_code_block_append(ast_parser, &value->data.procedure->exec_block);
				return_statement->type = AST_STATEMENT_RETURN;
				return_statement->src_loc_id = value->data.procedure->exec_block.instructions[value->data.procedure->exec_block.instruction_count - 2].src_loc_id;
			}
			else
				PANIC(ast_parser, ERROR_UNRETURNED_FUNCTION);
		}

		ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
		break;
	}
	case TOK_FOREIGN: {
		value->value_type = AST_VALUE_FOREIGN;
		PANIC_ON_FAIL(value->data.foreign = safe_malloc(ast_parser->safe_gc, sizeof(ast_foreign_call_t)), ast_parser, ERROR_MEMORY);
		value->type = *type;
		READ_TOK;
		MATCH_TOK(TOK_OPEN_BRACKET);
		READ_TOK;
		ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.foreign->op_id, &typecheck_int, 0, 0));
		MATCH_TOK(TOK_CLOSE_BRACKET);
		READ_TOK;
		if (LAST_TOK.type == TOK_OPEN_PAREN) {
			PANIC_ON_FAIL(value->data.foreign->input = safe_malloc(ast_parser->safe_gc, sizeof(ast_value_t)), ast_parser, ERROR_MEMORY);
			READ_TOK;
			typecheck_type_t t = { .type = TYPE_AUTO };
			ESCAPE_ON_FAIL(parse_expression(ast_parser, value->data.foreign->input, &t, 0, 0));
			free_typecheck_type(ast_parser->safe_gc, &t);
			MATCH_TOK(TOK_CLOSE_PAREN);
			READ_TOK;
		}
		else
			value->data.foreign->input = NULL;
		break;
	}
	default:
		PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
	}
	value->id = ast_parser->ast->value_count++;

	int has_incremented = 0;
	while (LAST_TOK.type == TOK_OPEN_BRACKET || LAST_TOK.type == TOK_OPEN_PAREN || LAST_TOK.type == TOK_IS_TYPE || LAST_TOK.type == TOK_INCREMENT || LAST_TOK.type == TOK_DECREMENT || LAST_TOK.type == TOK_PERIOD || (LAST_TOK.type == TOK_LESS && value->type.type == TYPE_SUPER_PROC)) {
		if (LAST_TOK.type == TOK_IS_TYPE) {
			READ_TOK;

			ast_value_t cast_val = *value;
			PANIC_ON_FAIL(cast_val.type.type == TYPE_SUPER_RECORD || cast_val.type.type == TYPE_TYPEARG, ast_parser, ERROR_UNEXPECTED_TYPE);

			value->value_type = AST_VALUE_TYPE_OP;
			PANIC_ON_FAIL(value->data.type_op = safe_malloc(ast_parser->safe_gc, sizeof(ast_type_op_t)), ast_parser, ERROR_MEMORY);
			value->data.type_op->operand = cast_val;

			ESCAPE_ON_FAIL(parse_type(ast_parser, &value->data.type_op->match_type, 0, 0));
			if (typecheck_has_type(value->data.type_op->match_type, TYPE_TYPEARG))
				PANIC_ON_FAIL(CURRENT_FRAME.return_type, ast_parser, ERROR_UNEXPECTED_TYPE);
			//PANIC_ON_FAIL(value->data.type_op->match_type.type == TYPE_SUPER_RECORD || value->data.type_op->match_type.type == TYPE_TYPEARG, ast_parser, ERROR_UNEXPECTED_TYPE);

			value->data.type_op->operation = TOK_IS_TYPE;
			value->type.type = TYPE_PRIMITIVE_BOOL;
		}
		else if (LAST_TOK.type == TOK_OPEN_BRACKET) {
			READ_TOK;
			ast_value_t array_val, index_val;
			array_val = *value;

			PANIC_ON_FAIL(TYPE_COMP(&array_val.type, typecheck_array), ast_parser, ERROR_UNEXPECTED_TYPE);

			ESCAPE_ON_FAIL(parse_expression(ast_parser, &index_val, &typecheck_int, 0, 0));
			if (index_val.value_type == AST_VALUE_PRIMITIVE && index_val.data.primitive->data.long_int < 0)
				PANIC(ast_parser, ERROR_INDEX_OUT_OF_RANGE);
			MATCH_TOK(TOK_CLOSE_BRACKET);
			READ_TOK;
			if (LAST_TOK.type == TOK_SET) {
				value->value_type = AST_VALUE_SET_INDEX;
				PANIC_ON_FAIL(value->data.set_index = safe_malloc(ast_parser->safe_gc, sizeof(ast_set_index_t)), ast_parser, ERROR_MEMORY);
				READ_TOK;
				value->data.set_index->array = array_val;
				value->data.set_index->index = index_val;
				ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.set_index->value, &array_val.type.sub_types[0], 0, 0));
				TYPE_COPY(&value->type, value->data.set_index->value.type);
			}
			else {
				value->value_type = AST_VALUE_GET_INDEX;
				PANIC_ON_FAIL(value->data.get_index = safe_malloc(ast_parser->safe_gc, sizeof(ast_get_index_t)), ast_parser, ERROR_MEMORY);
				value->data.get_index->array = array_val;
				value->data.get_index->index = index_val;
				TYPE_COPY(&value->type, array_val.type.sub_types[0]);
			}
		}
		else if (LAST_TOK.type == TOK_PERIOD) {
			READ_TOK;

			ast_value_t record_val = *value;
			TYPE_COPY(&record_val.type, *devolve_type_from_generic(ast_parser, &record_val.type));
			PANIC_ON_FAIL(record_val.type.type == TYPE_SUPER_RECORD, ast_parser, ERROR_UNEXPECTED_TYPE);
			free_typecheck_type(ast_parser->safe_gc, &value->type);

			ast_record_prop_t* property;
			MATCH_TOK(TOK_IDENTIFIER);
			uint64_t id = hash_s(LAST_TOK.str, LAST_TOK.length);
			READ_TOK;
			ast_record_proto_t* record_proto = ast_parser->ast->record_protos[record_val.type.type_id];

			property = ast_record_find_prop(ast_parser, record_proto, id);
			PANIC_ON_FAIL(property, ast_parser, ERROR_UNDECLARED);
			typecheck_type_t prop_type;
			ESCAPE_ON_FAIL(ast_record_sub_prop_type(ast_parser, record_val.type, id, &prop_type));

			if (LAST_TOK.type == TOK_SET) {
				value->value_type = AST_VALUE_SET_PROP;
				PANIC_ON_FAIL(!property->is_readonly, ast_parser, ERROR_READONLY);
				PANIC_ON_FAIL(value->data.set_prop = safe_malloc(ast_parser->safe_gc, sizeof(ast_set_prop_t)), ast_parser, ERROR_MEMORY);
				value->data.set_prop->record = record_val;
				value->data.set_prop->property = property;
				READ_TOK;
				ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.set_prop->value, &prop_type, 0, 0));
				free_typecheck_type(ast_parser->safe_gc, &prop_type);
				TYPE_COPY(&value->type, value->data.set_prop->value.type);
			}
			else {
				value->value_type = AST_VALUE_GET_PROP;
				PANIC_ON_FAIL(value->data.get_prop = safe_malloc(ast_parser->safe_gc, sizeof(ast_get_prop_t)), ast_parser, ERROR_MEMORY);
				value->data.get_prop->record = record_val;
				value->data.get_prop->property = property;
				value->type = prop_type;
			}
		}
		else if (LAST_TOK.type == TOK_OPEN_PAREN || (LAST_TOK.type == TOK_LESS && value->type.type == TYPE_SUPER_PROC)) {
			ast_value_t proc_val = *value;

			TYPE_COPY(&proc_val.type, *devolve_type_from_generic(ast_parser, &proc_val.type));
			PANIC_ON_FAIL(proc_val.type.type == TYPE_SUPER_PROC, ast_parser, ERROR_UNEXPECTED_TYPE);
			free_typecheck_type(ast_parser->safe_gc, &value->type);

			value->value_type = AST_VALUE_PROC_CALL;
			PANIC_ON_FAIL(value->data.proc_call = safe_malloc(ast_parser->safe_gc, sizeof(ast_call_proc_t)), ast_parser, ERROR_MEMORY);

			typecheck_type_t call_type;
			TYPE_COPY(&call_type, proc_val.type);
			if (call_type.type_id) {
				ESCAPE_ON_FAIL(parse_subtypes(ast_parser, &value->type, call_type.sub_types, call_type.type_id));
				PANIC_ON_FAIL(typeargs_substitute(ast_parser->safe_gc, value->data.proc_call->typeargs = value->type.sub_types, &call_type), ast_parser, ERROR_MEMORY);
			}

			value->data.proc_call->procedure = proc_val;
			value->data.proc_call->argument_count = 0;
			value->data.proc_call->id = ast_parser->ast->proc_call_count++;
			TYPE_COPY(&value->type, call_type.sub_types[call_type.type_id]);
			READ_TOK;

			while (LAST_TOK.type != TOK_CLOSE_PAREN) {
				if (value->data.proc_call->argument_count == TYPE_MAX_SUBTYPES || value->data.proc_call->argument_count == call_type.sub_type_count - 1)
					PANIC(ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);
				ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.proc_call->arguments[value->data.proc_call->argument_count], &call_type.sub_types[value->data.proc_call->argument_count + 1 + call_type.type_id], 0, 0));
				value->data.proc_call->argument_count++;
				if (LAST_TOK.type != TOK_COMMA)
					MATCH_TOK(TOK_CLOSE_PAREN)
				else
					READ_TOK;
			}
			if (value->data.proc_call->argument_count < call_type.sub_type_count - (1 + call_type.type_id))
				PANIC(ast_parser, ERROR_UNEXPECTED_ARGUMENT_SIZE);

			free_typecheck_type(ast_parser->safe_gc, &call_type);
			READ_TOK;
		}
		else if (LAST_TOK.type == TOK_INCREMENT || LAST_TOK.type == TOK_DECREMENT) {
			if (has_incremented)
				PANIC(ast_parser, ERROR_UNEXPECTED_TOK);
			has_incremented = 1;

			ast_value_t operand = *value;
			PANIC_ON_FAIL(TYPE_COMP(&operand.type, typecheck_int) || TYPE_COMP(&operand.type, typecheck_float), ast_parser, ERROR_UNEXPECTED_TYPE);
			if (!(operand.value_type == AST_VALUE_VAR || operand.value_type == AST_VALUE_SET_VAR))
				PANIC(ast_parser, ERROR_UNEXPECTED_TOK);

			value->value_type = AST_VALUE_UNARY_OP;
			PANIC_ON_FAIL(value->data.unary_op = safe_malloc(ast_parser->safe_gc, sizeof(ast_unary_op_t)), ast_parser, ERROR_MEMORY);
			value->data.unary_op->operator = LAST_TOK.type;
			value->data.unary_op->is_postfix = 1;
			value->data.unary_op->operand = operand;

			TYPE_COPY(&value->type, operand.type);
			READ_TOK;
		}
		value->id = ast_parser->ast->value_count++;
		value->is_falsey = value->is_truey = 0;
		value->src_loc_id = src_loc_id;
	}
	PANIC_ON_FAIL(TYPE_COMP(type, value->type), ast_parser, ERROR_UNEXPECTED_TYPE);
	return 1;
}

static int parse_expression(ast_parser_t* ast_parser, ast_value_t* value, typecheck_type_t* type, int allow_auto, int min_prec) {
	static int op_precs[] = {
		2, 2, 2, 2, 2, 2,
		3, 3, 4, 4, 4, 5,
		1, 1
	};

	ast_value_t lhs;
	lhs.type = (typecheck_type_t){ .type = TYPE_AUTO };
	ESCAPE_ON_FAIL(parse_value(ast_parser, &lhs, &lhs.type));
	while (LAST_TOK.type >= TOK_EQUALS && LAST_TOK.type <= TOK_OR && op_precs[LAST_TOK.type - TOK_EQUALS] > min_prec) {
		PANIC_ON_FAIL(value->data.binary_op = safe_malloc(ast_parser->safe_gc, sizeof(ast_binary_op_t)), ast_parser, ERROR_MEMORY);
		value->data.binary_op->operator = LAST_TOK.type;
		value->value_type = AST_VALUE_BINARY_OP;
		READ_TOK;

		if (value->data.binary_op->operator >= TOK_EQUALS && value->data.binary_op->operator <= TOK_LESS_EQUAL)
			value->type.type = TYPE_PRIMITIVE_BOOL;
		else if (value->data.binary_op->operator >= TOK_AND && value->data.binary_op->operator <= TOK_OR) {
			PANIC_ON_FAIL(TYPE_COMP(&lhs.type, typecheck_bool), ast_parser, ERROR_UNEXPECTED_TYPE);
			value->type.type = TYPE_PRIMITIVE_BOOL;
		}

		ESCAPE_ON_FAIL(parse_expression(ast_parser, &value->data.binary_op->rhs, &lhs.type, 1, op_precs[value->data.binary_op->operator - TOK_EQUALS]));

		if (lhs.type.type == TYPE_AUTO) {
			PANIC_ON_FAIL(value->data.binary_op->rhs.type.type != TYPE_AUTO, ast_parser, ERROR_UNEXPECTED_TYPE);
			TYPE_COPY(&lhs.type, value->data.binary_op->rhs.type);
		}
		else if (value->data.binary_op->rhs.type.type == TYPE_AUTO) {
			PANIC_ON_FAIL(lhs.type.type == TYPE_AUTO, ast_parser, ERROR_UNEXPECTED_TYPE);
			TYPE_COPY(&value->data.binary_op->rhs.type, lhs.type);
		}
		else
			PANIC_ON_FAIL(TYPE_COMP(&lhs.type, value->data.binary_op->rhs.type), ast_parser, ERROR_UNEXPECTED_TYPE);

		if (value->data.binary_op->operator >= TOK_ADD && value->data.binary_op->operator <= TOK_POWER) {
			PANIC_ON_FAIL(TYPE_COMP(&lhs.type, typecheck_int) || TYPE_COMP(&lhs.type, typecheck_float), ast_parser, ERROR_UNEXPECTED_TYPE);
			value->type = lhs.type;
		}

		//divide by zero hard coded check
		if ((value->data.binary_op->operator == TOK_DIVIDE)
			&& (lhs.type.type == TYPE_PRIMITIVE_LONG && value->data.binary_op->rhs.data.primitive->data.long_int == 0))
			PANIC(ast_parser, ERROR_DIVIDE_BY_ZERO);

		value->id = ast_parser->ast->value_count++;
		value->is_falsey = value->is_truey = 0;
		value->data.binary_op->lhs = lhs;
		value->src_loc_id = lhs.src_loc_id;
		lhs = *value;
	}
	if (type->type == TYPE_AUTO) {
		if (lhs.type.type == TYPE_AUTO && !allow_auto)
			PANIC(ast_parser, ERROR_UNEXPECTED_TYPE);
		TYPE_COPY(type, lhs.type);
	}
	else
		PANIC_ON_FAIL(TYPE_COMP(&lhs.type, *type), ast_parser, ERROR_UNEXPECTED_TYPE);

	*value = lhs;
	return 1;
}

int init_ast(ast_t* ast, ast_parser_t* ast_parser, dbg_table_t* dbg_table) {
	ast_parser->ast = ast;
	ast->dbg_table = dbg_table;
	ast->proc_call_count = 0;
	ast->value_count = 0;
	ast->constant_count = 0;
	ast->var_decl_count = 0;
	ast->proc_count = 0;
	ast->constant_count = 0;
	ast->record_count = 0;

	PANIC_ON_FAIL(ast->record_protos = safe_malloc(ast_parser->safe_gc, (ast->allocated_records = 4) * sizeof(ast_record_proto_t*)), ast_parser, ERROR_MEMORY);
	PANIC_ON_FAIL(ast->primitives = safe_malloc(ast_parser->safe_gc, (ast->allocated_constants = 10) * sizeof(ast_primitive_t*)), ast_parser, ERROR_MEMORY);

	READ_TOK;
	ESCAPE_ON_FAIL(ast_parser_new_frame(ast_parser, NULL, 0));
	ESCAPE_ON_FAIL(parse_code_block(ast_parser, &ast->exec_block, 0, 0));
	ast_parser->top_level_local_count = CURRENT_FRAME.max_scoped_locals;
	ESCAPE_ON_FAIL(ast_parser_close_frame(ast_parser));
	ESCAPE_ON_FAIL(ast_postproc(ast_parser));
	return 1;
}