#include <string.h>
#include "ast.h"
#include "postproc.h"

#ifdef _DEBUG
static uint16_t sanitize_scope_id(uint16_t scope_id, uint16_t limit) {
	if (scope_id > limit)
		abort();
	return scope_id;
}
#define SANITIZE_SCOPE_ID(VAR_INFO) sanitize_scope_id((VAR_INFO).scope_id, (VAR_INFO).is_global ? ast_parser->global_count : local_scope_size)
#else
#define SANITIZE_SCOPE_ID(VAR_INFO) (VAR_INFO).scope_id
#endif

static int comes_from_used_var(ast_value_t value) {
	switch (value.value_type) {
	case AST_VALUE_ALLOC_ARRAY:
	case AST_VALUE_PRIMITIVE:
	case AST_VALUE_BINARY_OP:
	case AST_VALUE_UNARY_OP:
	case AST_VALUE_PROC:
		return 0;
	case AST_VALUE_TYPE_OP:
		return comes_from_used_var(value.data.type_op->operand);
	case AST_VALUE_PROC_CALL:
	case AST_VALUE_FOREIGN:
		return 1;
	case AST_VALUE_ALLOC_RECORD:
		for (uint_fast16_t i = 0; i < value.data.alloc_record.init_value_count; i++)
			if (comes_from_used_var(value.data.alloc_record.init_values[i].value))
				return 1;
		return 0;
	case AST_VALUE_ARRAY_LITERAL:
		for (uint_fast16_t i = 0; i < value.data.array_literal.element_count; i++)
			if (comes_from_used_var(value.data.array_literal.elements[i]))
				return 1;
		return 0;
	case AST_VALUE_VAR:
		return value.data.variable->is_used;
	case AST_VALUE_SET_VAR:
		return value.data.set_var->var_info->is_used || comes_from_used_var(value.data.set_var->set_value);
	case AST_VALUE_SET_INDEX:
		return comes_from_used_var(value.data.set_index->array) || comes_from_used_var(value.data.set_index->value);
	case AST_VALUE_SET_PROP:
		return comes_from_used_var(value.data.set_prop->record) || comes_from_used_var(value.data.set_prop->value);
	case AST_VALUE_GET_INDEX:
		return comes_from_used_var(value.data.get_index->array);
	case AST_VALUE_GET_PROP:
		return comes_from_used_var(value.data.get_prop->record);
	}
}

#define CHECK_AFFECTS_STATE(AFFECT_STATE, VALUE) { if(ast_postproc_value_affects_state(AFFECT_STATE, VALUE, second_pass)) {changes_made = 1;} if((VALUE)->affects_state) {value->affects_state = 1;} }

static int ast_postproc_codeblock_affects_state(ast_code_block_t* code_block, int second_pass);

static void mark_code_block_no_affects_state(ast_code_block_t* code_block);

static void mark_value_no_affect_state(ast_value_t* value) {
	value->affects_state = 0;
	switch (value->value_type)
	{
	case AST_VALUE_ALLOC_RECORD:
		for (uint_fast16_t i = 0; i < value->data.alloc_record.init_value_count; i++)
			mark_value_no_affect_state(&value->data.alloc_record.init_values[i].value);
		break;
	case AST_VALUE_ARRAY_LITERAL:
		for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++)
			mark_value_no_affect_state(&value->data.array_literal.elements[i]);
		break;
	case AST_VALUE_PROC:
		mark_code_block_no_affects_state(&value->data.procedure->exec_block);
		break;
	case AST_VALUE_SET_VAR:
		mark_value_no_affect_state(&value->data.set_var->set_value);
		break;
	case AST_VALUE_SET_INDEX:
		mark_value_no_affect_state(&value->data.set_index->array);
		mark_value_no_affect_state(&value->data.set_index->index);
		mark_value_no_affect_state(&value->data.set_index->value);
		break;
	case AST_VALUE_SET_PROP:
		mark_value_no_affect_state(&value->data.set_prop->record);
		mark_value_no_affect_state(&value->data.set_prop->value);
		break;
	case AST_VALUE_GET_INDEX:
		mark_value_no_affect_state(&value->data.get_index->array);
		mark_value_no_affect_state(&value->data.get_index->index);
		break;
	case AST_VALUE_GET_PROP:
		mark_value_no_affect_state(&value->data.get_prop->record);
		break;
	case AST_VALUE_BINARY_OP:
		mark_value_no_affect_state(&value->data.binary_op->lhs);
		mark_value_no_affect_state(&value->data.binary_op->rhs);
		break;
	case AST_VALUE_UNARY_OP:
		mark_value_no_affect_state(&value->data.unary_op->operand);
		break;
	case AST_VALUE_TYPE_OP:
		mark_value_no_affect_state(&value->data.type_op->operand);
		break;
	case AST_VALUE_FOREIGN:
		if (value->data.foreign->input)
			mark_value_no_affect_state(value->data.foreign->input);
		mark_value_no_affect_state(&value->data.foreign->op_id);
		break;
	case AST_VALUE_PROC_CALL:
		mark_value_no_affect_state(&value->data.proc_call->procedure);
		for (uint_fast16_t i = 0; i < value->data.proc_call->argument_count; i++)
			mark_value_no_affect_state(&value->data.proc_call->arguments[i]);
		break;
	}
}

static void mark_code_block_no_affects_state(ast_code_block_t* code_block) {
	for (ast_statement_t* current_statement = code_block->instructions; current_statement != &code_block->instructions[code_block->instruction_count]; current_statement++) {
		switch (current_statement->type)
		{
		case AST_STATEMENT_DECL_VAR:
			mark_value_no_affect_state(&current_statement->data.var_decl.set_value);
			break;
		case AST_STATEMENT_COND:{
			ast_cond_t* current_cond = current_statement->data.conditional; 
			while (current_cond)
			{
				if (current_cond->condition)
					mark_value_no_affect_state(current_cond->condition);
				mark_code_block_no_affects_state(&current_cond->exec_block);
				current_cond = current_cond->next_if_false;
			}
			break;
		}
		case AST_STATEMENT_VALUE:
		case AST_STATEMENT_RETURN_VALUE:
			mark_value_no_affect_state(&current_statement->data.value);
			break;
		}
	}
}

static int ast_postproc_value_affects_state(int affects_state, ast_value_t* value, int second_pass) {
	int changes_made = 0;
	value->affects_state = affects_state;
	switch (value->value_type)
	{
	case AST_VALUE_ALLOC_ARRAY:
		CHECK_AFFECTS_STATE(affects_state, &value->data.alloc_array->size);
		break;
	case AST_VALUE_ALLOC_RECORD:
		for (uint_fast16_t i = 0; i < value->data.alloc_record.init_value_count; i++)
			CHECK_AFFECTS_STATE(affects_state, &value->data.alloc_record.init_values[i].value);
		break;
	case AST_VALUE_ARRAY_LITERAL:
		for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++)
			CHECK_AFFECTS_STATE(affects_state, &value->data.array_literal.elements[i]);
		break;
	case AST_VALUE_PROC:
		if (affects_state)
			changes_made = ast_postproc_codeblock_affects_state(&value->data.procedure->exec_block, second_pass);
		else
			mark_code_block_no_affects_state(&value->data.procedure->exec_block);
		break;
	case AST_VALUE_VAR:
		if (affects_state && !value->data.variable->is_used) {
			value->data.variable->is_used = 1;
			changes_made = 1;
		}
		break;
	case AST_VALUE_SET_VAR:
		if (affects_state && !value->data.set_var->var_info->is_used) {
			value->data.set_var->var_info->is_used = 1;
			changes_made = 1;
		}
		CHECK_AFFECTS_STATE(value->data.set_var->var_info->is_used, &value->data.set_var->set_value);
		value->affects_state = value->data.set_var->var_info->is_used || value->affects_state;
		break;
	case AST_VALUE_SET_INDEX:
		if (second_pass)
			value->affects_state = value->affects_state || value->data.set_index->array.gc_status == POSTPROC_GC_EXTERN_ALLOC || value->data.set_index->array.gc_status == POSTPROC_GC_UNKOWN_ALLOC;
		value->affects_state = value->affects_state || comes_from_used_var(value->data.set_index->array);
		CHECK_AFFECTS_STATE(value->affects_state, &value->data.set_index->array);
		CHECK_AFFECTS_STATE(value->affects_state, &value->data.set_index->index);
		CHECK_AFFECTS_STATE(value->affects_state, &value->data.set_index->value);
		break;
	case AST_VALUE_SET_PROP:
		if(second_pass)
			value->affects_state = value->affects_state || value->data.set_prop->record.gc_status == POSTPROC_GC_EXTERN_ALLOC || value->data.set_prop->record.gc_status == POSTPROC_GC_UNKOWN_ALLOC;
		value->affects_state = value->affects_state || comes_from_used_var(value->data.set_prop->record);
		CHECK_AFFECTS_STATE(value->affects_state, &value->data.set_prop->record);
		CHECK_AFFECTS_STATE(value->affects_state, &value->data.set_prop->value);
		break;
	case AST_VALUE_GET_INDEX:
		CHECK_AFFECTS_STATE(affects_state, &value->data.get_index->array)
		CHECK_AFFECTS_STATE(affects_state, &value->data.get_index->index);
		break;
	case AST_VALUE_GET_PROP:
		CHECK_AFFECTS_STATE(affects_state, &value->data.get_prop->record);
		break;
	case AST_VALUE_BINARY_OP:
		CHECK_AFFECTS_STATE(affects_state, &value->data.binary_op->lhs);
		CHECK_AFFECTS_STATE(affects_state, &value->data.binary_op->rhs);
		break;
	case AST_VALUE_UNARY_OP:
		CHECK_AFFECTS_STATE(affects_state, &value->data.unary_op->operand);
		break;
	case AST_VALUE_TYPE_OP:
		CHECK_AFFECTS_STATE(affects_state, &value->data.type_op->operand);
		break;
	case AST_VALUE_FOREIGN:
		value->affects_state = 1;
		CHECK_AFFECTS_STATE(1, &value->data.foreign->op_id);
		if(value->data.foreign->input)
			CHECK_AFFECTS_STATE(1, value->data.foreign->input);
		break;
	case AST_VALUE_PROC_CALL:
		value->affects_state = 1;
		CHECK_AFFECTS_STATE(1, &value->data.proc_call->procedure);
		for (uint_fast8_t i = 0; i < value->data.proc_call->argument_count; i++)
			CHECK_AFFECTS_STATE(1, &value->data.proc_call->arguments[i]);
		break;
	}
	return changes_made;
}
#undef CHECK_AFFECTS_STATE

#define CHECK_AFFECTS_STATE(CALL) if(CALL) {changes_made = 1;}
static int ast_postproc_codeblock_affects_state(ast_code_block_t* code_block, int second_pass) {
	int changes_made = 0;
	for (ast_statement_t* current_statement = code_block->instructions; current_statement != &code_block->instructions[code_block->instruction_count]; current_statement++) {
		switch (current_statement->type)
		{
		case AST_STATEMENT_DECL_VAR:
			CHECK_AFFECTS_STATE(ast_postproc_value_affects_state(current_statement->data.var_decl.var_info->is_used, &current_statement->data.var_decl.set_value, second_pass));
			break;
		case AST_STATEMENT_RECORD_PROTO: {
			if (!second_pass) {
				for (uint_fast16_t i = 0; i < current_statement->data.record_proto->default_value_count; i++)
					CHECK_AFFECTS_STATE(ast_postproc_value_affects_state(1, &current_statement->data.record_proto->default_values[i].value, 0));
			}
			break;
		}
		case AST_STATEMENT_COND: {
			ast_cond_t* current_cond = current_statement->data.conditional;
			while (current_cond) {
				if(current_cond->condition)
					CHECK_AFFECTS_STATE(ast_postproc_value_affects_state(1, current_cond->condition, second_pass));
				CHECK_AFFECTS_STATE(ast_postproc_codeblock_affects_state(&current_cond->exec_block, second_pass));
				current_cond = current_cond->next_if_false;
			}
			break;
		}
		case AST_STATEMENT_VALUE:
			CHECK_AFFECTS_STATE(ast_postproc_value_affects_state(0, &current_statement->data.value, second_pass));
			break;
		case AST_STATEMENT_RETURN_VALUE:
			CHECK_AFFECTS_STATE(ast_postproc_value_affects_state(1, &current_statement->data.value, second_pass));
			break;
		}
	}
	return changes_made;
}
#undef CHECK_AFFECTS_STATE

static int ast_postproc_value(ast_parser_t* ast_parser, ast_value_t* value, postproc_trace_status_t* typearg_traces, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, int* shared_globals, int* shared_locals, uint16_t local_scope_size, postproc_parent_status_t parent_stat, ast_proc_t* parent_proc);

static int ast_postproc_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, postproc_trace_status_t* trace_stats, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, uint16_t local_scope_size, int* shared_globals, int* shared_locals, int is_top_level, ast_proc_t* parent_proc) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++)
		switch (code_block->instructions[i].type)
		{
		case AST_STATEMENT_DECL_VAR: {
			ast_var_info_t* var_info = code_block->instructions[i].data.var_decl.var_info;
			ast_value_t* set_value = &code_block->instructions[i].data.var_decl.set_value;
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, set_value, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats, is_top_level ? ast_parser->shared_globals : shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			if (var_info->is_global) {
				ast_parser->top_level_global_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = set_value->gc_status;
				if (set_value->gc_status == POSTPROC_GC_LOCAL_ALLOC || set_value->gc_status == POSTPROC_GC_UNKOWN_ALLOC)
					ast_parser->global_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = POSTPROC_GC_SUPEREXT_ALLOC;
				else
					ast_parser->global_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = set_value->gc_status;
				ast_parser->shared_globals[SANITIZE_SCOPE_ID(*var_info)] = set_value->from_var;
			}
			else {
				local_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = set_value->gc_status;
				shared_locals[SANITIZE_SCOPE_ID(*var_info)] = set_value->from_var;
			}
			break;
		}
		case AST_STATEMENT_COND: {
			ast_cond_t* current_cond = code_block->instructions[i].data.conditional;
			while (current_cond) {
				if (current_cond->condition)
					ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, current_cond->condition, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats, is_top_level ? ast_parser->shared_globals : shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));

				postproc_gc_status_t* new_gc_context = safe_malloc(ast_parser->safe_gc, local_scope_size * sizeof(postproc_gc_status_t));
				PANIC_ON_FAIL(new_gc_context, ast_parser, ERROR_MEMORY);
				postproc_gc_status_t* new_global_stats = safe_malloc(ast_parser->safe_gc, ast_parser->global_count * sizeof(postproc_gc_status_t));
				PANIC_ON_FAIL(new_global_stats, ast_parser, ERROR_MEMORY);
				memcpy(new_global_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, ast_parser->global_count * sizeof(postproc_gc_status_t));
				int* new_shared_locals = safe_malloc(ast_parser->safe_gc, local_scope_size * sizeof(int));
				PANIC_ON_FAIL(new_shared_locals, ast_parser, ERROR_MEMORY);
				int* new_shared_globals = safe_malloc(ast_parser->safe_gc, ast_parser->global_count * sizeof(int));
				PANIC_ON_FAIL(new_shared_globals, ast_parser, ERROR_MEMORY);
				memcpy(new_gc_context, local_gc_stats, local_scope_size * sizeof(postproc_gc_status_t));
				memcpy(new_shared_locals, shared_locals, local_scope_size * sizeof(int));
				memcpy(new_shared_globals, is_top_level ? ast_parser->shared_globals : shared_globals, ast_parser->global_count * sizeof(int));

				ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &current_cond->exec_block, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : new_global_stats, new_gc_context, local_scope_size, new_shared_globals, new_shared_locals, is_top_level, parent_proc));
				safe_free(ast_parser->safe_gc, new_gc_context);
				safe_free(ast_parser->safe_gc, new_global_stats);
				safe_free(ast_parser->safe_gc, new_shared_locals);
				safe_free(ast_parser->safe_gc, new_shared_globals);
				current_cond = current_cond->next_if_false;
			}
			break;
		}
		case AST_STATEMENT_VALUE:
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &code_block->instructions[i].data.value, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats, is_top_level ? ast_parser->shared_globals : shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
			break;
		case AST_STATEMENT_RETURN_VALUE:
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &code_block->instructions[i].data.value, trace_stats, global_gc_stats, local_gc_stats, is_top_level ? ast_parser->shared_globals : shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc));
			break;
		}
	return 1;
}

static postproc_gc_status_t postproc_type_to_gc_stat(postproc_gc_status_t parent_val_gc, typecheck_base_type_t base_type) {
	if (parent_val_gc == POSTPROC_GC_EXTERN_ALLOC) {
		switch (base_type) {
		case TYPE_TYPEARG:
			return POSTPROC_GC_EXTERN_DYNAMIC;
		case TYPE_SUPER_ARRAY:
		case TYPE_SUPER_RECORD:
			return POSTPROC_GC_EXTERN_ALLOC;
		default:
			return POSTPROC_GC_NONE;
		}
	}
	else if (parent_val_gc == POSTPROC_GC_SUPEREXT_ALLOC) {
		switch (base_type) {
		case TYPE_SUPER_ARRAY:
		case TYPE_SUPER_RECORD:
			return POSTPROC_GC_SUPEREXT_ALLOC;
		default:
			return POSTPROC_GC_NONE;
		}
	}
	else switch (base_type) {
	case TYPE_TYPEARG:
		return POSTPROC_GC_LOCAL_DYNAMIC;
	case TYPE_SUPER_ARRAY:
	case TYPE_SUPER_RECORD:
		return POSTPROC_GC_LOCAL_ALLOC;
	default:
		return POSTPROC_GC_NONE;
	}
}

static void share_var_from_value(ast_parser_t* ast_parser, ast_value_t value, int* shared_globals, int* shared_locals, uint16_t local_scope_size) {
	switch (value.value_type) {
	case AST_VALUE_VAR:
		if (value.data.variable->is_global)
			shared_globals[SANITIZE_SCOPE_ID(*value.data.variable)] = 1;
		else
			shared_locals[SANITIZE_SCOPE_ID(*value.data.variable)] = 1;
		break;
	case AST_VALUE_SET_VAR:
		if (value.data.set_var->var_info->is_global)
			shared_globals[SANITIZE_SCOPE_ID(*value.data.set_var->var_info)] = 1;
		else
			shared_locals[SANITIZE_SCOPE_ID(*value.data.set_var->var_info)] = 1;
		break;
	case AST_VALUE_TYPE_OP:
		if(value.data.type_op->operation == TOK_DYNAMIC_CAST)
			share_var_from_value(ast_parser, value.data.type_op->operand, shared_globals, shared_locals, local_scope_size);
		break;
	case AST_VALUE_SET_INDEX:
		share_var_from_value(ast_parser, value.data.set_index->array, shared_globals, shared_locals, local_scope_size);
		break;
	case AST_VALUE_GET_INDEX:
		share_var_from_value(ast_parser, value.data.get_index->array, shared_globals, shared_locals, local_scope_size);
		break;
	case AST_VALUE_SET_PROP:
		share_var_from_value(ast_parser, value.data.set_prop->record, shared_globals, shared_locals, local_scope_size);
		break;
	case AST_VALUE_GET_PROP:
		share_var_from_value(ast_parser, value.data.get_prop->record, shared_globals, shared_locals, local_scope_size);
		break;
	}
}

#define GET_TYPE_TRACE(TYPE) (((TYPE).type == TYPE_TYPEARG) ? typearg_traces[(TYPE).type_id] : IS_REF_TYPE(TYPE))
#define GET_TYPE_FREE(TYPE) (((TYPE).type != TYPE_TYPEARG) ? IS_REF_TYPE(TYPE) : (typearg_traces[(TYPE).type_id] == POSTPROC_TRACE_DYNAMIC ? POSTPROC_FREE_DYNAMIC : POSTPROC_FREE))
#define PROC_DO_GC if(parent_proc && value->affects_state) {parent_proc->do_gc = 1;};

static int ast_postproc_value(ast_parser_t* ast_parser, ast_value_t* value, postproc_trace_status_t* typearg_traces, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, int* shared_globals, int* shared_locals, uint16_t local_scope_size, postproc_parent_status_t parent_stat, ast_proc_t* parent_proc) {
	value->free_status = POSTPROC_FREE_NONE;
	value->from_var = 0;

	switch (value->value_type) {
	case AST_VALUE_PRIMITIVE:
		value->gc_status = POSTPROC_GC_NONE;
		break;
	case AST_VALUE_ALLOC_ARRAY:
		PROC_DO_GC;
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.alloc_array->size, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		break;
	case AST_VALUE_ARRAY_LITERAL:
		PROC_DO_GC;
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		value->data.array_literal.children_trace = GET_TYPE_TRACE(*value->data.array_literal.elem_type);
		for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.array_literal.elements[i], typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, parent_stat, parent_proc));
			if (value->data.array_literal.elements[i].from_var && value->data.array_literal.elements[i].trace_status != POSTPROC_TRACE_NONE)
				value->from_var = 1;
		}
		break;
	case AST_VALUE_ALLOC_RECORD: {
		PROC_DO_GC;
		PANIC_ON_FAIL(value->data.alloc_record.typearg_traces = safe_malloc(ast_parser->safe_gc, (value->data.alloc_record.proto->index_offset + value->data.alloc_record.proto->property_count) * sizeof(postproc_trace_status_t)), ast_parser, ERROR_MEMORY);

		typecheck_type_t* current_typeargs = safe_malloc(ast_parser->safe_gc, TYPE_MAX_SUBTYPES * sizeof(typecheck_type_t));
		PANIC_ON_FAIL(current_typeargs, ast_parser, ERROR_MEMORY);
		memcpy(current_typeargs, value->type.sub_types, value->type.sub_type_count * sizeof(typecheck_type_t));

		ast_record_proto_t* current_proto = value->data.alloc_record.proto;
		for (;;) {
			for (uint_fast8_t i = 0; i < current_proto->property_count; i++) {
				typecheck_type_t actual_type;

				if (current_proto->properties[i].type.type == TYPE_TYPEARG)
					actual_type = current_typeargs[current_proto->properties[i].type.type_id];
				else
					actual_type = current_proto->properties[i].type;
				if (actual_type.type == TYPE_TYPEARG)
					value->data.alloc_record.typearg_traces[current_proto->properties[i].id] = POSTPROC_TRACE_DYNAMIC;
				else
					value->data.alloc_record.typearg_traces[current_proto->properties[i].id] = IS_REF_TYPE(actual_type);
			}

			if (current_proto->base_record) {
				static typecheck_type_t new_typeargs[TYPE_MAX_SUBTYPES];
				memcpy(new_typeargs, current_proto->base_record->sub_types, current_proto->base_record->sub_type_count * sizeof(typecheck_type_t));
				for (uint_fast8_t i = 0; i < current_proto->base_record->sub_type_count; i++)
					if (current_proto->base_record->sub_types[i].type == TYPE_TYPEARG)
						new_typeargs[i] = current_typeargs[current_proto->base_record->sub_types[i].type_id];
				memcpy(current_typeargs, new_typeargs, current_proto->base_record->sub_type_count * sizeof(typecheck_type_t));
				current_proto = ast_parser->ast->record_protos[current_proto->base_record->type_id];
			}
			else break;
		}
		safe_free(ast_parser->safe_gc, current_typeargs);

		for (uint_fast16_t i = 0; i < value->data.alloc_record.init_value_count; i++) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.alloc_record.init_values[i].value, value->data.alloc_record.typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, parent_stat, parent_proc));
			if (value->data.alloc_record.init_values[i].value.from_var && value->data.alloc_record.typearg_traces[value->data.alloc_record.init_values[i].property->id] != POSTPROC_TRACE_NONE)
				value->from_var = 1;
		}
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		break;
	}
	case AST_VALUE_PROC: {
		value->trace_status = POSTPROC_TRACE_NONE;
		value->gc_status = POSTPROC_GC_NONE;

		postproc_gc_status_t* new_local_stats = safe_malloc(ast_parser->safe_gc, value->data.procedure->scope_size * sizeof(postproc_gc_status_t));
		PANIC_ON_FAIL(new_local_stats, ast_parser, ERROR_MEMORY);
		postproc_gc_status_t* new_global_stats = safe_malloc(ast_parser->safe_gc, ast_parser->global_count * sizeof(int));
		PANIC_ON_FAIL(new_global_stats, ast_parser, ERROR_MEMORY);
		memcpy(new_global_stats, ast_parser->global_gc_stats, ast_parser->global_count * sizeof(postproc_gc_status_t));
		int* new_shared_locals = safe_calloc(ast_parser->safe_gc, value->data.procedure->scope_size, sizeof(int));
		PANIC_ON_FAIL(new_shared_locals, ast_parser, ERROR_MEMORY);
		int* new_shared_globals = safe_malloc(ast_parser->safe_gc, ast_parser->global_count * sizeof(int));
		PANIC_ON_FAIL(new_shared_globals, ast_parser, ERROR_MEMORY);
		memcpy(new_shared_globals, ast_parser->shared_globals, ast_parser->global_count * sizeof(int));
		value->data.procedure->generic_arg_traces = safe_malloc(ast_parser->safe_gc, value->type.type_id * sizeof(postproc_trace_status_t));
		PANIC_ON_FAIL(value->data.procedure->generic_arg_traces, ast_parser, ERROR_MEMORY);

		for (uint_fast8_t i = 0; i < value->type.type_id; i++) {
			if (value->type.sub_types[i].type == TYPE_ANY)
				value->data.procedure->generic_arg_traces[i] = POSTPROC_TRACE_DYNAMIC;
			else
				value->data.procedure->generic_arg_traces[i] = GET_TYPE_TRACE(value->type.sub_types[i]);
		}
		
		for (uint_fast8_t i = 0; i < value->data.procedure->param_count; i++) {
			if (value->data.procedure->params[i].type.type == TYPE_TYPEARG)
				new_local_stats[value->data.procedure->params[i].scope_id] = POSTPROC_GC_EXTERN_DYNAMIC;
			else if (IS_REF_TYPE(value->data.procedure->params[i].type))
				new_local_stats[value->data.procedure->params[i].scope_id] = POSTPROC_GC_EXTERN_ALLOC;
			else
				new_local_stats[value->data.procedure->params[i].scope_id] = POSTPROC_GC_NONE;
		}

		value->data.procedure->do_gc = 0;
		ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &value->data.procedure->exec_block, value->data.procedure->generic_arg_traces, new_global_stats, new_local_stats, value->data.procedure->scope_size, new_shared_globals, new_shared_locals, 0, value->data.procedure));

		safe_free(ast_parser->safe_gc, new_local_stats);
		safe_free(ast_parser->safe_gc, new_global_stats);
		safe_free(ast_parser->safe_gc, new_shared_locals);
		safe_free(ast_parser->safe_gc, new_shared_globals);
		break;
	}
	case AST_VALUE_VAR:
		value->from_var = 1;
		if (value->data.variable->is_global) {
			value->gc_status = global_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)];
			if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
				shared_globals[SANITIZE_SCOPE_ID(*value->data.variable)] = 1;
			break;
		}
		else {
			value->gc_status = local_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)];
			if ((value->gc_status == POSTPROC_GC_LOCAL_ALLOC || value->gc_status == POSTPROC_GC_UNKOWN_ALLOC || value->gc_status == POSTPROC_GC_LOCAL_DYNAMIC) && parent_stat == POSTPROC_PARENT_EXTERN) {
				value->trace_status = GET_TYPE_TRACE(value->data.variable->type);
				local_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)] = value->gc_status = value->gc_status == POSTPROC_GC_LOCAL_DYNAMIC ? POSTPROC_GC_EXTERN_DYNAMIC : POSTPROC_GC_TRACED_ALLOC;
			}
			else if ((value->gc_status == POSTPROC_GC_EXTERN_ALLOC || value->gc_status == POSTPROC_GC_LOCAL_ALLOC || value->gc_status == POSTPROC_GC_UNKOWN_ALLOC) && parent_stat == POSTPROC_PARENT_SUPEREXT) {
				value->trace_status = GET_TYPE_TRACE(value->data.variable->type);
				if (value->trace_status == POSTPROC_TRACE_CHILDREN)
					value->trace_status = POSTPROC_SUPERTRACE_CHILDREN;
				local_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)] = value->gc_status = POSTPROC_GC_SUPEREXT_ALLOC;
			}
			else {
				if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
					shared_locals[SANITIZE_SCOPE_ID(*value->data.variable)] = 1;
				value->trace_status = POSTPROC_TRACE_NONE;
			}
			goto no_trace_postproc;
		}
	case AST_VALUE_SET_VAR:
		value->from_var = 1;
		if (!value->data.set_var->var_info->is_used) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
			value->gc_status = POSTPROC_GC_NONE;
			break;
		}
		else if (value->data.set_var->var_info->is_global) {
			value->gc_status = global_gc_stats[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)];
			if (value->gc_status == POSTPROC_GC_EXTERN_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
			else if (value->gc_status == POSTPROC_GC_SUPEREXT_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_SUPEREXT, parent_proc))
			else
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));

			value->gc_status = global_gc_stats[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->data.set_var->set_value.gc_status;
			value->data.set_var->free_status = shared_globals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] ? POSTPROC_FREE_NONE : GET_TYPE_FREE(value->data.set_var->var_info->type);
			shared_globals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->from_var;
			if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
				shared_globals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = 1;
		}
		else {
			value->gc_status = local_gc_stats[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)];
			
			if(value->gc_status == POSTPROC_GC_SUPEREXT_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_SUPEREXT, parent_proc))
			else
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));

			value->gc_status = local_gc_stats[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->data.set_var->set_value.gc_status;
			value->data.set_var->free_status = shared_locals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] ? POSTPROC_FREE_NONE : GET_TYPE_FREE(value->data.set_var->var_info->type);
			shared_locals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->from_var;
			if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
				shared_locals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = 1;
		}
		break;
	case AST_VALUE_SET_INDEX:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->index, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		if (value->data.set_index->array.gc_status == POSTPROC_GC_EXTERN_ALLOC)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
		else if (value->data.set_index->array.gc_status == POSTPROC_GC_SUPEREXT_ALLOC || value->data.set_index->array.gc_status == POSTPROC_GC_UNKOWN_ALLOC)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_SUPEREXT, parent_proc))
		else {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			if (value->data.set_index->value.gc_status == POSTPROC_GC_EXTERN_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
			else if (value->data.set_index->value.gc_status == POSTPROC_GC_SUPEREXT_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_SUPEREXT, parent_proc))
		}
		if (value->data.set_index->value.from_var && value->data.set_index->value.trace_status != POSTPROC_TRACE_NONE)
			share_var_from_value(ast_parser, value->data.set_index->array, shared_globals, shared_locals, local_scope_size);
		value->gc_status = value->data.set_index->value.gc_status;
		value->from_var = value->data.set_index->array.from_var || value->data.set_index->value.from_var;
		break;
	case AST_VALUE_GET_INDEX:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, GET_TYPE_TRACE(value->data.get_index->array.type) == POSTPROC_TRACE_NONE ? POSTPROC_PARENT_IRRELEVANT : parent_stat, parent_proc));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_index->index, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(value->data.get_index->array.gc_status, value->data.get_index->array.type.sub_types[0].type);
		value->from_var = value->data.get_index->array.from_var;
		break;
	case AST_VALUE_SET_PROP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		if (value->data.set_prop->record.gc_status == POSTPROC_GC_EXTERN_ALLOC)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
		else if (value->data.set_prop->record.gc_status == POSTPROC_GC_SUPEREXT_ALLOC || value->data.set_prop->record.gc_status == POSTPROC_GC_UNKOWN_ALLOC)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_SUPEREXT, parent_proc))
		else {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			if (value->data.set_prop->value.gc_status == POSTPROC_GC_EXTERN_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
			else if (value->data.set_prop->value.gc_status == POSTPROC_GC_SUPEREXT_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_SUPEREXT, parent_proc))
		}
		if (value->data.set_prop->value.from_var && value->data.set_prop->value.trace_status != POSTPROC_TRACE_NONE)
			share_var_from_value(ast_parser, value->data.set_prop->record, shared_globals, shared_locals, local_scope_size);
		value->gc_status = value->data.set_prop->value.gc_status;
		value->from_var = value->data.set_prop->record.from_var || value->data.set_prop->value.from_var;
		break;
	case AST_VALUE_GET_PROP: {
		typecheck_type_t prop_type;
		ESCAPE_ON_FAIL(ast_record_sub_prop_type(ast_parser, value->data.get_prop->record.type, value->data.get_prop->property->hash_id, &prop_type));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, GET_TYPE_TRACE(prop_type) == POSTPROC_TRACE_NONE ? POSTPROC_PARENT_IRRELEVANT : parent_stat, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(value->data.get_prop->record.gc_status, prop_type.type);
		value->from_var = value->data.get_prop->record.from_var;
		free_typecheck_type(ast_parser->safe_gc, &prop_type);
		break;
	}
	case AST_VALUE_BINARY_OP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.binary_op->lhs, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.binary_op->rhs, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = POSTPROC_GC_NONE;
		break;
	case AST_VALUE_UNARY_OP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.unary_op->operand, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = POSTPROC_GC_NONE;
		break;
	case AST_VALUE_TYPE_OP:
		if (value->data.type_op->operation == TOK_IS_TYPE) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.type_op->operand, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
			value->gc_status = POSTPROC_GC_NONE;
		}
		else {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.type_op->operand, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, parent_stat, parent_proc));
			value->gc_status = value->data.type_op->operand.gc_status;
			value->from_var = value->data.type_op->operand.from_var;
		}
		break;
	case AST_VALUE_PROC_CALL:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.proc_call->procedure, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		PANIC_ON_FAIL(value->data.proc_call->typearg_traces = safe_malloc(ast_parser->safe_gc, value->data.proc_call->procedure.type.type_id * sizeof(postproc_trace_status_t)), ast_parser, ERROR_MEMORY);
		if (value->data.proc_call->procedure.type.type_id) {
			for (uint_fast8_t i = 0; i < value->data.proc_call->procedure.type.type_id; i++)
				if (value->data.proc_call->typeargs[i].type == TYPE_TYPEARG)
					value->data.proc_call->typearg_traces[i] = typearg_traces[value->data.proc_call->typeargs[i].type_id];
				else
					value->data.proc_call->typearg_traces[i] = IS_REF_TYPE(value->data.proc_call->typeargs[i]);
		}

		for (uint_fast8_t i = 0; i < value->data.proc_call->argument_count; i++) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.proc_call->arguments[i], typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
			if ((value->data.proc_call->arguments[i].gc_status == POSTPROC_GC_SUPEREXT_ALLOC || value->data.proc_call->arguments[i].gc_status == POSTPROC_GC_UNKOWN_ALLOC) && parent_proc) {
				value->data.proc_call->arguments[i].trace_status = POSTPROC_SUPERTRACE_CHILDREN;
				value->data.proc_call->arguments[i].gc_status = POSTPROC_GC_SUPERTRACED_ALLOC;
			}
			else if (value->data.proc_call->arguments[i].gc_status == POSTPROC_GC_EXTERN_ALLOC) {
				value->data.proc_call->arguments[i].trace_status = POSTPROC_TRACE_CHILDREN;
				value->data.proc_call->arguments[i].gc_status = POSTPROC_GC_TRACED_ALLOC;
			}
		}
		if (IS_REF_TYPE(value->type))
			value->gc_status = POSTPROC_GC_UNKOWN_ALLOC;
		else if (value->type.type == TYPE_TYPEARG)
			value->gc_status = POSTPROC_GC_LOCAL_DYNAMIC;
		else
			value->gc_status = POSTPROC_GC_NONE;
		value->from_var = 1;
		break;
	case AST_VALUE_FOREIGN:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.foreign->op_id, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		if (value->data.foreign->input)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, value->data.foreign->input, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(POSTPROC_GC_LOCAL_ALLOC, value->type.type);
		break;
	}

	if (value->gc_status == POSTPROC_GC_NONE || parent_stat == POSTPROC_PARENT_IRRELEVANT) {
		if (parent_stat == POSTPROC_PARENT_IRRELEVANT && !value->from_var && value->gc_status == POSTPROC_GC_LOCAL_ALLOC)
			value->free_status = GET_TYPE_FREE(value->type);
		value->trace_status = POSTPROC_TRACE_NONE;
		goto no_trace_postproc;
	}

	switch (parent_stat) {
	case POSTPROC_PARENT_EXTERN:
		if (value->gc_status == POSTPROC_GC_LOCAL_ALLOC || value->gc_status == POSTPROC_GC_UNKOWN_ALLOC) {
			value->trace_status = POSTPROC_TRACE_CHILDREN;
			value->gc_status = POSTPROC_GC_TRACED_ALLOC;
		}
		else if (value->gc_status == POSTPROC_GC_LOCAL_DYNAMIC) {
			value->trace_status = GET_TYPE_TRACE(value->type);
			value->gc_status = POSTPROC_GC_EXTERN_DYNAMIC;
		}
		break;
	case POSTPROC_PARENT_SUPEREXT:
		if (value->gc_status == POSTPROC_GC_LOCAL_ALLOC || value->gc_status == POSTPROC_GC_UNKOWN_ALLOC || value->gc_status == POSTPROC_GC_EXTERN_ALLOC) {
			value->trace_status = POSTPROC_SUPERTRACE_CHILDREN;
			value->gc_status = POSTPROC_GC_SUPERTRACED_ALLOC;
		}
		else
			value->trace_status = POSTPROC_TRACE_NONE;
		break;
	case POSTPROC_PARENT_LOCAL:
		value->trace_status = POSTPROC_TRACE_NONE;
		break;
	}

no_trace_postproc:
	return 1;
}
#undef GET_TYPE_TRACE
#undef PROC_DO_GC
#undef SANITIZE_SCOPE_ID

int ast_postproc_link_record(ast_parser_t* ast_parser, ast_record_proto_t* record, uint16_t* out) {
	if (!record->linked) {
		PANIC_ON_FAIL(record->fully_defined, ast_parser, ERROR_UNDECLARED);

		if (record->base_record) {
			ESCAPE_ON_FAIL(ast_postproc_link_record(ast_parser, ast_parser->ast->record_protos[record->base_record->type_id], &record->index_offset));
			record->do_gc = ast_parser->ast->record_protos[record->base_record->type_id]->do_gc;
		}
		else
			record->index_offset = 0;
		
		for (uint_fast8_t i = 0; i < record->property_count; i++) {
			if (IS_REF_TYPE(record->properties[i].type))
				record->do_gc = 1;
			record->properties[i].id += record->index_offset;
		}
		record->linked = 1;
	}
	if(out)
		*out = record->index_offset + record->property_count;
	return 1;
}

int ast_postproc(ast_parser_t* ast_parser) {
	//link record/struct definitions
	for (uint_fast8_t i = 0; i < ast_parser->ast->record_count; i++)
		PANIC_ON_FAIL(ast_parser->ast->record_protos[i]->fully_defined, ast_parser, ERROR_UNDECLARED);
	for (uint_fast8_t i = 0; i < ast_parser->ast->record_count; i++)
		ESCAPE_ON_FAIL(ast_postproc_link_record(ast_parser, ast_parser->ast->record_protos[i], NULL));

	while (ast_postproc_codeblock_affects_state(&ast_parser->ast->exec_block, 0)) {}

	//allocate memory used for analysis
	PANIC_ON_FAIL(ast_parser->top_level_global_gc_stats = safe_malloc(ast_parser->safe_gc, ast_parser->global_count * sizeof(postproc_gc_status_t)), ast_parser, ERROR_MEMORY);
	PANIC_ON_FAIL(ast_parser->global_gc_stats = safe_malloc(ast_parser->safe_gc, ast_parser->global_count * sizeof(postproc_gc_status_t)), ast_parser, ERROR_MEMORY);
	postproc_gc_status_t* top_level_locals = safe_malloc(ast_parser->safe_gc, ast_parser->top_level_local_count * sizeof(postproc_gc_status_t));
	PANIC_ON_FAIL(top_level_locals, ast_parser, ERROR_MEMORY);
	PANIC_ON_FAIL(ast_parser->shared_globals = safe_calloc(ast_parser->safe_gc, ast_parser->global_count, sizeof(int)), ast_parser, ERROR_MEMORY);
	int* shared_top_level = safe_calloc(ast_parser->safe_gc, ast_parser->top_level_local_count, sizeof(int));
	PANIC_ON_FAIL(shared_top_level, ast_parser, ERROR_MEMORY);
	ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &ast_parser->ast->exec_block, NULL, NULL, top_level_locals, ast_parser->top_level_local_count, NULL, shared_top_level, 1, NULL));

	while (ast_postproc_codeblock_affects_state(&ast_parser->ast->exec_block, 1)) {}

	safe_free(ast_parser->safe_gc, shared_top_level);
	safe_free(ast_parser->safe_gc, top_level_locals);
	safe_free(ast_parser->safe_gc, ast_parser->shared_globals);
	safe_free(ast_parser->safe_gc, ast_parser->global_gc_stats);
	safe_free(ast_parser->safe_gc, ast_parser->top_level_global_gc_stats);
	return 1;
}