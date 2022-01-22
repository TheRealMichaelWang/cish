#include <stdlib.h>
#include <string.h>
#include "ast.h"
#include "postproc.h"

static int ast_postproc_value(ast_parser_t* ast_parser, ast_value_t* value, postproc_trace_status_t* trace_stats, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats);

static int ast_postproc_code_block(ast_parser_t* ast_parser, ast_code_block_t* code_block, postproc_trace_status_t* trace_stats, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats, uint16_t local_scope_size, int is_top_level) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++)
		switch (code_block->instructions[i].type)
		{
		case AST_STATEMENT_DECL_VAR: {
			ast_var_info_t* var_info = code_block->instructions[i].data.var_decl.var_info;
			ast_value_t* set_value = &code_block->instructions[i].data.var_decl.set_value;
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, set_value, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats));
			if (var_info->is_global)
				switch (set_value->gc_status) {
				case POSTPROC_GC_NONE:
				case POSTPROC_GC_EXTERN_ALLOC:
					ast_parser->top_level_global_gc_stats[var_info->scope_id] = global_gc_stats[var_info->scope_id] = POSTPROC_GC_NONE;
					break;
				case POSTPROC_GC_LOCAL_ALLOC:
					global_gc_stats[var_info->scope_id] = POSTPROC_GC_EXTERN_ALLOC;
					ast_parser->top_level_global_gc_stats[var_info->scope_id] = POSTPROC_GC_LOCAL_ALLOC;
				}
			else
				local_gc_stats[var_info->scope_id] = set_value->gc_status;
			break;
		}
		case AST_STATEMENT_COND: {
			ast_cond_t* current_cond = code_block->instructions[i].data.conditional;
			while (current_cond) {
				if (current_cond->condition)
					ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, current_cond->condition, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats))

					postproc_gc_status_t* new_gc_context = malloc(local_scope_size * sizeof(postproc_gc_status_t));
				PANIC_ON_FAIL(new_gc_context, ast_parser, ERROR_MEMORY);
				memcpy(new_gc_context, local_gc_stats, local_scope_size * sizeof(postproc_gc_status_t));

				ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &current_cond->exec_block, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, new_gc_context, local_scope_size, is_top_level));
				free(new_gc_context);
				current_cond = current_cond->next_if_false;
			}
			break;
		}
		case AST_STATEMENT_VALUE:
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &code_block->instructions[i].data.value, trace_stats, is_top_level ? ast_parser->top_level_global_gc_stats : global_gc_stats, local_gc_stats));
			break;
		case AST_STATEMENT_RETURN_VALUE:
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &code_block->instructions[i].data.value, trace_stats, global_gc_stats, local_gc_stats));
			break;
		}
	return 1;
}

static void ast_gcproc_setchild(postproc_gc_status_t parent_gc_stat, ast_value_t child, postproc_trace_status_t* trace_stat, postproc_gc_status_t* set_stat, postproc_trace_status_t* typearg_traces) {
	if (parent_gc_stat == POSTPROC_GC_EXTERN_ALLOC) {
		switch (child.gc_status) {
		case POSTPROC_GC_EXTERN_ALLOC:
		case POSTPROC_GC_EXTERN_DYNAMIC:
		case POSTPROC_GC_NONE:
			*trace_stat = POSTPROC_TRACE_NONE;
			break;
		case POSTPROC_GC_LOCAL_ALLOC:
			*trace_stat = POSTPROC_TRACE_CHILDREN;
			break;
		case POSTPROC_GC_LOCAL_DYNAMIC:
			*trace_stat = typearg_traces[child.type.type_id];
			break;
		}
	}
	else {
		switch (child.gc_status) {
		case POSTPROC_GC_LOCAL_ALLOC:
		case POSTPROC_GC_LOCAL_DYNAMIC:
		case POSTPROC_GC_EXTERN_DYNAMIC:
		case POSTPROC_GC_NONE:
			*trace_stat = POSTPROC_TRACE_NONE;
			break;
		case POSTPROC_GC_EXTERN_ALLOC:
			*trace_stat = POSTPROC_TRACE_CHILDREN;
			break;
		}
	}
	if (set_stat)
		*set_stat = child.gc_status;
}

static postproc_gc_status_t ast_getchild_gc_status(typecheck_type_t parent_type, postproc_gc_status_t parent_gc_stat) {
	if (IS_REF_TYPE(parent_type))
		if (parent_gc_stat == POSTPROC_GC_EXTERN_ALLOC)
			return POSTPROC_GC_EXTERN_ALLOC;
		else
			return POSTPROC_GC_LOCAL_ALLOC;
	else if (parent_type.type == TYPE_TYPEARG)
		if (parent_gc_stat == POSTPROC_GC_EXTERN_ALLOC)
			return POSTPROC_GC_EXTERN_DYNAMIC;
		else
			return POSTPROC_GC_LOCAL_DYNAMIC;
	else
		return POSTPROC_GC_NONE;
}

static int ast_postproc_value(ast_parser_t* ast_parser, ast_value_t* value, postproc_trace_status_t* typearg_traces, postproc_gc_status_t* global_gc_stats, postproc_gc_status_t* local_gc_stats) {
	switch (value->value_type) {
	case AST_VALUE_PRIMITIVE:
		value->gc_status = POSTPROC_GC_NONE;
		break;
	case AST_VALUE_ALLOC_ARRAY:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.alloc_array->size, typearg_traces, global_gc_stats, local_gc_stats));
		if (value->data.alloc_array->elem_type->type == TYPE_TYPEARG)
			value->data.alloc_array->gc_trace = typearg_traces[value->data.alloc_array->elem_type->type_id];
		else
			value->data.alloc_array->gc_trace = IS_REF_TYPE(*value->data.alloc_array->elem_type);
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		break;
	case AST_VALUE_ALLOC_RECORD: {
		PANIC_ON_FAIL(value->data.alloc_record.typearg_traces = malloc((value->data.alloc_record.proto->index_offset + value->data.alloc_record.proto->property_count) * sizeof(postproc_trace_status_t)), ast_parser, ERROR_MEMORY);

		static typecheck_type_t current_typeargs[TYPE_MAX_SUBTYPES];
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
		free(overriden_defaults);

		for (uint_fast16_t i = 0; i < value->data.alloc_record.init_value_count; i++) {
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, value->data.alloc_record.init_values[i].value, value->data.alloc_record.typearg_traces, global_gc_stats, local_gc_stats));
			ast_gcproc_setchild(POSTPROC_GC_LOCAL_ALLOC, *value->data.alloc_record.init_values[i].value, &value->data.alloc_record.init_values[i].gc_trace, NULL, value->data.alloc_record.typearg_traces);
		}
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		break;
	}
	case AST_VALUE_ARRAY_LITERAL:
		value->gc_status = POSTPROC_GC_LOCAL_ALLOC;
		for (uint_fast16_t i = 0; i < value->data.array_literal.element_count; i++)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.array_literal.elements[i], typearg_traces, global_gc_stats, local_gc_stats));
		if (value->data.array_literal.elem_type->type == TYPE_TYPEARG)
			value->data.array_literal.gc_trace = typearg_traces[value->data.array_literal.elem_type->type_id];
		else
			value->data.array_literal.gc_trace = IS_REF_TYPE(*value->data.array_literal.elem_type);
		break;
	case AST_VALUE_PROC: {
		value->gc_status = POSTPROC_GC_NONE;
		postproc_gc_status_t* new_local_stats = malloc(value->data.procedure->scope_size * sizeof(postproc_gc_status_t));
		PANIC_ON_FAIL(new_local_stats, ast_parser, ERROR_MEMORY);
		postproc_trace_status_t* typearg_traces = malloc(value->type.type_id * sizeof(postproc_trace_status_t));
		for (uint_fast8_t i = 0; i < value->type.type_id; i++)
			typearg_traces[i] = POSTPROC_TRACE_DYNAMIC;
		for (uint_fast8_t i = 0; i < value->data.procedure->param_count; i++)
			if (value->data.procedure->params[i].var_info.type.type == TYPE_TYPEARG)
				new_local_stats[value->data.procedure->params[i].var_info.scope_id] = POSTPROC_GC_EXTERN_DYNAMIC;
			else if (IS_REF_TYPE(value->data.procedure->params[i].var_info.type))
				new_local_stats[value->data.procedure->params[i].var_info.scope_id] = POSTPROC_GC_EXTERN_ALLOC;
			else
				new_local_stats[value->data.procedure->params[i].var_info.scope_id] = POSTPROC_GC_NONE;
		ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &value->data.procedure->exec_block, typearg_traces, global_gc_stats, new_local_stats, value->data.procedure->scope_size, 0));
		free(new_local_stats);
		free(typearg_traces);
		break;
	}
	case AST_VALUE_VAR:
		if (value->data.variable->is_global)
			value->gc_status = global_gc_stats[value->data.variable->scope_id];
		else
			value->gc_status = local_gc_stats[value->data.variable->scope_id];
		break;
	case AST_VALUE_SET_VAR:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_var->set_value, typearg_traces, global_gc_stats, local_gc_stats));
		if (value->data.set_var->var_info->is_global) {
			if (value->data.set_var->set_value.gc_status == POSTPROC_GC_LOCAL_ALLOC)
				value->data.set_var->gc_trace = POSTPROC_TRACE_CHILDREN;
			else if (value->data.set_var->set_value.gc_status == POSTPROC_GC_EXTERN_ALLOC || value->data.set_var->set_value.gc_status == POSTPROC_GC_NONE)
				value->data.set_var->gc_trace = POSTPROC_TRACE_NONE;
			value->gc_status = global_gc_stats[value->data.set_var->var_info->scope_id];
		}
		else {
			if (value->data.set_var->set_value.gc_status == POSTPROC_GC_NONE)
				value->data.set_var->gc_trace = POSTPROC_TRACE_NONE;
			else if (value->data.set_var->set_value.gc_status == POSTPROC_GC_EXTERN_ALLOC || value->data.set_var->set_value.gc_status == POSTPROC_GC_EXTERN_DYNAMIC)
				local_gc_stats[value->data.set_var->var_info->scope_id] = value->data.set_var->set_value.gc_status;
			value->gc_status = local_gc_stats[value->data.set_var->var_info->scope_id];
		}
		break;
	case AST_VALUE_SET_INDEX:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->array, typearg_traces, global_gc_stats, local_gc_stats));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->index, typearg_traces, global_gc_stats, local_gc_stats));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_index->value, typearg_traces, global_gc_stats, local_gc_stats));
		ast_gcproc_setchild(value->data.set_index->array.gc_status, value->data.set_index->value, &value->data.set_index->gc_trace, &value->gc_status, typearg_traces);
		break;
	case AST_VALUE_GET_INDEX:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_index->array, typearg_traces, global_gc_stats, local_gc_stats));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.get_index->index, typearg_traces, global_gc_stats, local_gc_stats));
		value->gc_status = ast_getchild_gc_status(value->type, value->data.get_index->array.gc_status);
		break;
	case AST_VALUE_SET_PROP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->value, typearg_traces, global_gc_stats, local_gc_stats));
		ast_gcproc_setchild(value->data.set_prop->record.gc_status, value->data.set_prop->value, &value->data.set_prop->gc_trace, &value->gc_status, typearg_traces);
		break;
	case AST_VALUE_GET_PROP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.set_prop->record, typearg_traces, global_gc_stats, local_gc_stats));
		value->gc_status = ast_getchild_gc_status(value->type, value->data.set_prop->record.gc_status);
		break;
	case AST_VALUE_BINARY_OP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.binary_op->lhs, typearg_traces, global_gc_stats, local_gc_stats));
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.binary_op->rhs, typearg_traces, global_gc_stats, local_gc_stats));
		value->gc_status = POSTPROC_GC_NONE;
		break;
	case AST_VALUE_UNARY_OP:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.unary_op->operand, typearg_traces, global_gc_stats, local_gc_stats));
		value->gc_status = POSTPROC_GC_NONE;
		break;
	case AST_VALUE_PROC_CALL:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.proc_call->procedure, typearg_traces, global_gc_stats, local_gc_stats));
		PANIC_ON_FAIL(value->data.proc_call->typearg_traces = malloc(value->data.proc_call->procedure.type.type_id * sizeof(postproc_trace_status_t)), ast_parser, ERROR_MEMORY);
		if (value->data.proc_call->procedure.type.type_id) {
			for (uint_fast8_t i = 0; i < value->data.proc_call->procedure.type.type_id; i++)
				if (value->data.proc_call->typeargs[i].type == TYPE_TYPEARG)
					value->data.proc_call->typearg_traces[i] = typearg_traces[value->data.proc_call->typeargs[i].type_id];
				else
					value->data.proc_call->typearg_traces[i] = IS_REF_TYPE(value->data.proc_call->typeargs[i]);
		}
		for (uint_fast8_t i = 0; i < value->data.proc_call->argument_count; i++)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.proc_call->arguments[i], typearg_traces, global_gc_stats, local_gc_stats));
		value->gc_status = ast_getchild_gc_status(value->type, POSTPROC_GC_LOCAL_ALLOC);
		break;
	case AST_VALUE_FOREIGN:
		ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, &value->data.foreign->op_id, typearg_traces, global_gc_stats, local_gc_stats));
		if (value->data.foreign->input)
			ESCAPE_ON_FAIL(ast_postproc_value(ast_parser, value->data.foreign->input, typearg_traces, global_gc_stats, local_gc_stats));
		value->gc_status = ast_getchild_gc_status(value->type, POSTPROC_GC_LOCAL_ALLOC);
		break;
	}
	return 1;
}

int ast_postproc(ast_parser_t* ast_parser) {
	PANIC_ON_FAIL(ast_parser->top_level_global_gc_stats = malloc(ast_parser->global_count * sizeof(postproc_gc_status_t)), ast_parser, ERROR_MEMORY);
	postproc_gc_status_t* global_gc_stats = malloc(ast_parser->global_count * sizeof(postproc_gc_status_t));
	PANIC_ON_FAIL(global_gc_stats, ast_parser, ERROR_MEMORY);
	postproc_gc_status_t* top_level_locals = malloc(ast_parser->top_level_local_count * sizeof(postproc_gc_status_t));
	PANIC_ON_FAIL(top_level_locals, ast_parser, ERROR_MEMORY);
	ESCAPE_ON_FAIL(ast_postproc_code_block(ast_parser, &ast_parser->ast->exec_block, NULL, global_gc_stats, top_level_locals, ast_parser->top_level_local_count, 1));
	free(global_gc_stats);
	free(top_level_locals);
	free(ast_parser->top_level_global_gc_stats);
	return 1;
}