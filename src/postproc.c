#include <stdlib.h>
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

static int ast_postproc_value(ast_parser_t* ast_parser, ast_value_t* value, postproc_trace_status_t* typearg_traces, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, int* shared_globals, int* shared_locals, uint16_t local_scope_size, postproc_parent_status_t parent_stat, ast_proc_t* parent_proc);

static int ast_postproc_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, postproc_trace_status_t* trace_stats, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, uint16_t local_scope_size, int* shared_globals, int* shared_locals, int is_top_level, ast_proc_t* parent_proc) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++)
		switch (code_block->instructions[i].type)
		{
		case AST_STATEMENT_DECL_VAR: {
			ast_var_info_t* var_info = code_block->instructions[i].data.var_decl.var_info;
			ast_value_t* set_value = &code_block->instructions[i].data.var_decl.set_value;
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, set_value, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			if (var_info->is_global) {
				ast_parser->top_level_global_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = set_value->gc_status;
				if (set_value->gc_status == POSTPROC_GC_LOCAL_ALLOC)
					global_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = POSTPROC_GC_EXTERN_ALLOC;
				else
					global_gc_stats[SANITIZE_SCOPE_ID(*var_info)] = set_value->gc_status;
				shared_globals[SANITIZE_SCOPE_ID(*var_info)] = set_value->from_var;
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
					ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, current_cond->condition, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc))

				postproc_gc_status_t* new_gc_context = malloc(local_scope_size * sizeof(postproc_gc_status_t));
				PANIC_ON_FAIL(new_gc_context, ast_parser, ERROR_MEMORY);
				int* new_shared_locals = malloc(local_scope_size * sizeof(int));
				PANIC_ON_FAIL(new_shared_locals, ast_parser, ERROR_MEMORY);
				int* new_shared_globals = malloc(ast_parser->global_count * sizeof(int));
				PANIC_ON_FAIL(new_shared_globals, ast_parser, ERROR_MEMORY);
				memcpy(new_gc_context, local_gc_stats, local_scope_size * sizeof(postproc_gc_status_t));
				memcpy(new_shared_locals, shared_locals, local_scope_size * sizeof(int));
				memcpy(new_shared_globals, shared_globals, ast_parser->global_count * sizeof(int));

				ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &current_cond->exec_block, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, new_gc_context, local_scope_size, new_shared_globals, new_shared_locals, is_top_level, parent_proc));
				free(new_gc_context);
				free(new_shared_locals);
				free(new_shared_globals);
				current_cond = current_cond->next_if_false;
			}
			break;
		}
		case AST_STATEMENT_VALUE:
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &code_block->instructions[i].data.value, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
			break;
		case AST_STATEMENT_RETURN_VALUE:
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &code_block->instructions[i].data.value, trace_stats, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc));
			break;
		}
	return 1;
}

static postproc_gc_status_t postproc_type_to_gc_stat(postproc_gc_status_t parent_stat, typecheck_base_type_t base_type) {
	if (parent_stat == POSTPROC_GC_EXTERN_ALLOC) {
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
	else switch (base_type) {
	case TYPE_TYPEARG:
		return POSTPROC_GC_EXTERN_DYNAMIC;
	case TYPE_SUPER_ARRAY:
	case TYPE_SUPER_RECORD:
		return POSTPROC_GC_EXTERN_ALLOC;
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

#define GET_TYPE_TRACE(TYPE) ((TYPE).type == TYPE_TYPEARG) ? typearg_traces[(TYPE).type_id] : IS_REF_TYPE(TYPE)
#define PROC_DO_GC if(parent_proc) {parent_proc->do_gc = 1;};

static int ast_postproc_value(ast_parser_t* ast_parser, ast_value_t* value, postproc_trace_status_t* typearg_traces, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, int* shared_globals, int* shared_locals, uint16_t local_scope_size, postproc_parent_status_t parent_stat, ast_proc_t* parent_proc) {
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
		PANIC_ON_FAIL(value->data.alloc_record.typearg_traces = malloc((value->data.alloc_record.proto->index_offset + value->data.alloc_record.proto->property_count) * sizeof(postproc_trace_status_t)), ast_parser, ERROR_MEMORY);

		typecheck_type_t* current_typeargs = malloc(TYPE_MAX_SUBTYPES * sizeof(typecheck_type_t));
		PANIC_ON_FAIL(current_typeargs, ast_parser, ERROR_MEMORY);
		memcpy(current_typeargs, value->type.sub_types, value->type.sub_type_count * sizeof(typecheck_type_t));

		int* overriden_defaults = calloc(value->data.alloc_record.proto->property_count + value->data.alloc_record.proto->index_offset, sizeof(int));
		PANIC_ON_FAIL(overriden_defaults, ast_parser, ERROR_MEMORY);
		for (uint_fast8_t i = 0; i < value->data.alloc_record.init_value_count; i++)
			overriden_defaults[value->data.alloc_record.init_values[i].property->id] = 1;

		ast_record_proto_t* current_proto = value->data.alloc_record.proto;
		for (;;) {
			for (uint_fast16_t i = 0; i < current_proto->default_value_count; i++)
				if (!overriden_defaults[current_proto->default_values[i].property->id]) {
					overriden_defaults[current_proto->default_values[i].property->id] = 1;
					if (value->data.alloc_record.init_value_count == value->data.alloc_record.allocated_init_values) {
						if (value->data.alloc_record.allocated_init_values) {
							struct ast_alloc_record_init_value* new_init_values = realloc(value->data.alloc_record.init_values, (value->data.alloc_record.allocated_init_values += 2) * sizeof(struct ast_alloc_record_init_value));
							PANIC_ON_FAIL(new_init_values, ast_parser, ERROR_MEMORY);
							value->data.alloc_record.init_values = new_init_values;
						}
						else
							PANIC_ON_FAIL(value->data.alloc_record.init_values = malloc((value->data.alloc_record.allocated_init_values = 5) * sizeof(struct ast_alloc_record_init_value)), ast_parser, ERROR_MEMORY);
					}
					value->data.alloc_record.init_values[value->data.alloc_record.init_value_count++] = (struct ast_alloc_record_init_value){
						.value = &current_proto->default_values[i].value,
						.property = current_proto->default_values[i].property,
						.free_val = 0
					};
					ast_parser->ast->constant_count += current_proto->default_values[i].constant_count;
				}

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
		free(current_typeargs);
		free(overriden_defaults);

		for (uint_fast16_t i = 0; i < value->data.alloc_record.init_value_count; i++) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, value->data.alloc_record.init_values[i].value, value->data.alloc_record.typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, parent_stat, parent_proc));
			if (value->data.alloc_record.init_values[i].value->from_var && value->data.alloc_record.typearg_traces[value->data.alloc_record.init_values[i].property->id] != POSTPROC_TRACE_NONE)
				value->from_var = 1;
		}
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		break; 
	}
	case AST_VALUE_PROC: {
		value->trace_status = POSTPROC_TRACE_NONE;
		value->gc_status = POSTPROC_GC_NONE;
		postproc_gc_status_t* new_local_stats = malloc(value->data.procedure->scope_size * sizeof(postproc_gc_status_t));
		PANIC_ON_FAIL(new_local_stats, ast_parser, ERROR_MEMORY);
		int* new_shared_locals = calloc(value->data.procedure->scope_size, sizeof(int));
		PANIC_ON_FAIL(new_shared_locals, ast_parser, ERROR_MEMORY);
		postproc_trace_status_t* typearg_traces = malloc(value->type.type_id * sizeof(postproc_trace_status_t));
		PANIC_ON_FAIL(typearg_traces, ast_parser, ERROR_MEMORY);
		for (uint_fast8_t i = 0; i < value->type.type_id; i++)
			typearg_traces[i] = POSTPROC_TRACE_DYNAMIC;
		for (uint_fast8_t i = 0; i < value->data.procedure->param_count; i++)
			if (value->data.procedure->params[i].var_info.type.type == TYPE_TYPEARG)
				new_local_stats[SANITIZE_SCOPE_ID(value->data.procedure->params[i].var_info)] = POSTPROC_GC_EXTERN_DYNAMIC;
			else if (IS_REF_TYPE(value->data.procedure->params[i].var_info.type))
				new_local_stats[SANITIZE_SCOPE_ID(value->data.procedure->params[i].var_info)] = POSTPROC_GC_EXTERN_ALLOC;
			else
				new_local_stats[SANITIZE_SCOPE_ID(value->data.procedure->params[i].var_info)] = POSTPROC_GC_NONE;
		value->data.procedure->do_gc = 0;
		ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &value->data.procedure->exec_block, typearg_traces, global_gc_stats, new_local_stats, value->data.procedure->scope_size, shared_globals, new_shared_locals, 0, value->data.procedure));
		free(new_local_stats);
		free(new_shared_locals);
		free(typearg_traces);
		break;
	}
	case AST_VALUE_VAR:
		if (value->data.variable->is_global) {
			value->gc_status = global_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)];
			if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
				shared_globals[SANITIZE_SCOPE_ID(*value->data.variable)] = 1;
			break;
		}
		else {
			value->gc_status = local_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)];
			if ((value->gc_status == POSTPROC_GC_LOCAL_ALLOC || value->gc_status == POSTPROC_GC_LOCAL_DYNAMIC) && parent_stat == POSTPROC_PARENT_EXTERN) {
				value->trace_status = GET_TYPE_TRACE(value->data.variable->type);
				local_gc_stats[SANITIZE_SCOPE_ID(*value->data.variable)] = value->gc_status = value->gc_status == POSTPROC_GC_LOCAL_ALLOC ? POSTPROC_GC_TRACED_ALLOC : POSTPROC_GC_EXTERN_DYNAMIC;
			}
			else {
				if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
					shared_locals[SANITIZE_SCOPE_ID(*value->data.variable)] = 1;
				value->trace_status = POSTPROC_TRACE_NONE;
			}
			goto no_trace_postproc;
		}
	case AST_VALUE_SET_VAR:
		if (value->data.set_var->var_info->is_global) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, value->gc_status == POSTPROC_GC_EXTERN_ALLOC ? POSTPROC_PARENT_EXTERN : POSTPROC_PARENT_LOCAL, parent_proc));
			value->gc_status = global_gc_stats[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)];
			value->data.set_var->free_status = shared_globals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] ? POSTPROC_FREE_NONE : GET_TYPE_TRACE(value->data.set_var->var_info->type);
			shared_globals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->from_var;
			if (parent_stat != POSTPROC_PARENT_IRRELEVANT)
				shared_globals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = 1;
		}
		else {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			value->gc_status = local_gc_stats[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->data.set_var->set_value.gc_status;
			value->data.set_var->free_status = shared_locals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] ? POSTPROC_FREE_NONE : GET_TYPE_TRACE(value->data.set_var->var_info->type);
			shared_locals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = value->from_var;
			if(parent_stat != POSTPROC_PARENT_IRRELEVANT)
				shared_locals[SANITIZE_SCOPE_ID(*value->data.set_var->var_info)] = 1;
		}
		break;
	case AST_VALUE_SET_INDEX:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->index, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		if (value->data.set_index->array.gc_status == POSTPROC_GC_EXTERN_ALLOC)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
		else {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			if (value->data.set_index->array.gc_status == POSTPROC_GC_LOCAL_ALLOC && value->data.set_index->value.gc_status == POSTPROC_GC_EXTERN_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
		}
		if(value->data.set_index->value.from_var && value->data.set_index->value.trace_status != POSTPROC_TRACE_NONE)
			share_var_from_value(ast_parser, value->data.set_index->array, shared_globals, shared_locals, local_scope_size);
		value->gc_status = value->data.set_index->value.gc_status;
		break;
	case AST_VALUE_GET_INDEX:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_index->array, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, GET_TYPE_TRACE(value->data.get_index->array.type) == POSTPROC_TRACE_NONE ? POSTPROC_PARENT_IRRELEVANT : parent_stat, parent_proc));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_index->index, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(value->data.get_index->array.gc_status, value->data.get_index->array.type.type);
		break;
	case AST_VALUE_SET_PROP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		if (value->data.set_prop->record.gc_status == POSTPROC_GC_EXTERN_ALLOC)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_EXTERN, parent_proc))
		else {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->value, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_LOCAL, parent_proc));
			if(value->data.set_prop->record.gc_status == POSTPROC_GC_LOCAL_ALLOC && value->data.set_prop->value.gc_status == POSTPROC_GC_EXTERN_ALLOC)
				ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_GC_EXTERN_ALLOC, parent_proc));
		}
		if (value->data.set_prop->value.from_var && value->data.set_prop->value.trace_status != POSTPROC_TRACE_NONE)
			share_var_from_value(ast_parser, value->data.set_prop->record, shared_globals, shared_locals, local_scope_size);
		value->gc_status = value->data.set_prop->value.gc_status;
		break;
	case AST_VALUE_GET_PROP: {
		typecheck_type_t prop_type;
		ESCAPE_ON_FAIL(ast_record_sub_prop_type(ast_parser, value->data.get_prop->record.type, value->data.get_prop->property->hash_id, &prop_type));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_prop->record, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, GET_TYPE_TRACE(prop_type) == POSTPROC_TRACE_NONE ? POSTPROC_PARENT_IRRELEVANT : parent_stat, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(value->data.get_prop->record.gc_status, prop_type.type);
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
	case AST_VALUE_PROC_CALL:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.proc_call->procedure, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		PANIC_ON_FAIL(value->data.proc_call->typearg_traces = malloc(value->data.proc_call->procedure.type.type_id * sizeof(postproc_trace_status_t)), ast_parser, ERROR_MEMORY);
		if (value->data.proc_call->procedure.type.type_id) {
			for (uint_fast8_t i = 0; i < value->data.proc_call->procedure.type.type_id; i++)
				if (value->data.proc_call->typeargs[i].type == TYPE_TYPEARG)
					value->data.proc_call->typearg_traces[i] = typearg_traces[value->data.proc_call->typeargs[i].type_id];
				else
					value->data.proc_call->typearg_traces[i] = IS_REF_TYPE(value->data.proc_call->typeargs[i]);
		}
		for (uint_fast8_t i = 0; i < value->data.proc_call->argument_count; i++)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.proc_call->arguments[i], typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(POSTPROC_GC_EXTERN_ALLOC, value->type.type);
		break;
	case AST_VALUE_FOREIGN:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.foreign->op_id, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		if (value->data.foreign->input)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, value->data.foreign->input, typearg_traces, global_gc_stats, local_gc_stats, shared_globals, shared_locals, local_scope_size, POSTPROC_PARENT_IRRELEVANT, parent_proc));
		value->gc_status = postproc_type_to_gc_stat(POSTPROC_GC_LOCAL_ALLOC, value->type.type);
		break;
	}

	if (value->gc_status == POSTPROC_GC_NONE || parent_stat == POSTPROC_PARENT_IRRELEVANT) {
		if (parent_stat == POSTPROC_PARENT_IRRELEVANT && !value->from_var && (value->gc_status != POSTPROC_GC_EXTERN_ALLOC && value->gc_status != POSTPROC_GC_EXTERN_DYNAMIC))
			value->free_status = GET_TYPE_TRACE(value->type);
		value->trace_status = POSTPROC_TRACE_NONE;
		goto no_trace_postproc;
	}

	value->free_status = POSTPROC_FREE_NONE;
	switch (parent_stat) {
	case POSTPROC_PARENT_EXTERN:
		if (value->gc_status == POSTPROC_GC_LOCAL_ALLOC) {
			value->trace_status = POSTPROC_TRACE_CHILDREN;
			value->gc_status = POSTPROC_GC_TRACED_ALLOC;
		}
		else if (value->gc_status == POSTPROC_GC_LOCAL_DYNAMIC) {
			value->trace_status = GET_TYPE_TRACE(value->type);
			value->gc_status = POSTPROC_GC_EXTERN_DYNAMIC;
		}
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

static int ast_postproc_link_record(ast_t* ast, ast_record_proto_t* record) {
	if (!record->defined) {
		if (record->base_record) {
			record->index_offset = ast_postproc_link_record(ast, ast->record_protos[record->base_record->type_id]);
			record->do_gc = ast->record_protos[record->base_record->type_id]->do_gc;
		}
		for (uint_fast8_t i = 0; i < record->property_count; i++) {
			if (IS_REF_TYPE(record->properties[i].type))
				record->do_gc = 1;
			record->properties[i].id += record->index_offset;
		}
		record->defined = 1;
	}
	return record->index_offset + record->property_count;
}

int ast_postproc(ast_parser_t* ast_parser) {
	//link record/struct definitions
	for (uint_fast8_t i = 0; i < ast_parser->ast->record_count; i++) {
		PANIC_ON_FAIL(ast_parser->ast->record_protos[i]->defined, ast_parser, ERROR_UNDECLARED);
		ast_parser->ast->record_protos[i]->defined = 0;
	}
	for (uint_fast8_t i = 0; i < ast_parser->ast->record_count; i++)
		ast_postproc_link_record(ast_parser->ast, ast_parser->ast->record_protos[i]);

	//allocate memory used for analysis
	PANIC_ON_FAIL(ast_parser->top_level_global_gc_stats = malloc(ast_parser->global_count * sizeof(postproc_gc_status_t)), ast_parser, ERROR_MEMORY);
	postproc_gc_status_t* global_gc_stats = malloc(ast_parser->global_count * sizeof(postproc_gc_status_t));
	PANIC_ON_FAIL(global_gc_stats, ast_parser, ERROR_MEMORY);
	postproc_gc_status_t* top_level_locals = malloc(ast_parser->top_level_local_count * sizeof(postproc_gc_status_t));
	PANIC_ON_FAIL(top_level_locals, ast_parser, ERROR_MEMORY);
	int* shared_globals = calloc(ast_parser->global_count, sizeof(int));
	PANIC_ON_FAIL(shared_globals, ast_parser, ERROR_MEMORY);
	int* shared_top_level = calloc(ast_parser->top_level_local_count, sizeof(int));
	PANIC_ON_FAIL(shared_top_level, ast_parser, ERROR_MEMORY);

	ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &ast_parser->ast->exec_block, NULL, global_gc_stats, top_level_locals, ast_parser->top_level_local_count, shared_globals, shared_top_level, 1, NULL));

	free(global_gc_stats);
	free(top_level_locals);
	free(ast_parser->top_level_global_gc_stats);
	return 1;
}