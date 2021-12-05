#include <stdlib.h>
#include <string.h>
#include "compiler.h"

#define LOC_REG(INDEX) (compiler_reg_t){.reg = (INDEX), .offset = 1}
#define GLOB_REG(INDEX) (compiler_reg_t){.reg = (INDEX), .offset = 0}

#define INS0(OP) (machine_ins_t){.op_code = OP}
#define INS1(OP, REG) (machine_ins_t){.op_code = OP, .a = REG.reg, .a_flag = REG.offset}
#define INS2(OP, REG, REG1) (machine_ins_t){.op_code = OP, .a = REG.reg, .a_flag = REG.offset, .b = REG1.reg, .b_flag = REG1.offset}
#define INS3(OP, REG, REG1, REG2) (machine_ins_t){.op_code = OP, .a = REG.reg, .a_flag = REG.offset, .b = REG1.reg, .b_flag = REG1.offset, .c = REG2.reg, .c_flag = REG2.offset}

#define EMIT_INS(INS) PANIC_ON_FAIL(ins_builder_append_ins(&compiler->ins_builder, INS), compiler, ERROR_MEMORY)

int init_ins_builder(ins_builder_t* ins_builder) {
	ESCAPE_ON_FAIL(ins_builder->instructions = malloc((ins_builder->alloced_ins = 64) * sizeof(machine_ins_t)));
	ins_builder->instruction_count = 0;
	return 1;
}

int ins_builder_append_ins(ins_builder_t* ins_builder, machine_ins_t ins) {
	if (ins_builder->instruction_count == ins_builder->alloced_ins) {
		machine_ins_t* new_ins = realloc(ins_builder->instructions, (ins_builder->alloced_ins *= 2) * sizeof(machine_ins_t));
		ESCAPE_ON_FAIL(new_ins);
		ins_builder->instructions = new_ins;
	}
	ins_builder->instructions[ins_builder->instruction_count++] = ins;
	return 1;
}

static void allocate_code_block_regs(compiler_t* compiler, ast_code_block_t code_block, uint16_t current_reg);

static uint16_t allocate_value_regs(compiler_t* compiler, ast_value_t value, uint16_t current_reg, compiler_reg_t* target_reg) {
	uint16_t extra_regs = current_reg;
	switch (value.value_type)
	{
	case AST_VALUE_PRIMITIVE:
		memcpy(&compiler->target_machine->stack[compiler->current_constant], &value.data.primitive.data, sizeof(uint64_t));
		compiler->eval_regs[value.id] = GLOB_REG(compiler->current_constant++);
		compiler->move_eval[value.id] = 1;
		return current_reg;
	case AST_VALUE_ALLOC_ARRAY:
		allocate_value_regs(compiler, value.data.alloc_array->size, current_reg, NULL);
		break;
	case AST_VALUE_ARRAY_LITERAL:
		for (uint_fast16_t i = 0; i < value.data.array_literal.element_count; i++)
			allocate_value_regs(compiler, value.data.array_literal.elements[i], current_reg, NULL);
		break;
	case AST_VALUE_ALLOC_RECORD: {
		ast_record_proto_t* current_proto = value.data.alloc_record.proto;
		do {
			for (uint_fast8_t i = 0; i < current_proto->property_count; i++) {
				for (uint_fast16_t j = 0; j < value.data.alloc_record.init_value_count; j++)
					if (value.data.alloc_record.init_values[j].property == &current_proto->properties[i]) {
						allocate_value_regs(compiler, *value.data.alloc_record.init_values[j].value, current_reg, NULL);
						goto break_continue;
					}
				if (current_proto->properties[i].default_value)
					allocate_value_regs(compiler, *current_proto->properties[i].default_value, current_reg, NULL);
			break_continue:;
			}
			if (current_proto->base_record)
				current_proto = compiler->ast->record_protos[current_proto->base_record->type_id];
			else
				current_proto = NULL;
		} while (current_proto);
		break;
	}
	case AST_VALUE_PROC: {
		compiler->eval_regs[value.id] = GLOB_REG(compiler->ast->total_constants + compiler->current_global++);
		compiler->move_eval[value.id] = 1;
		for (uint_fast16_t i = 0; i < value.data.procedure->param_count; i++)
			compiler->var_regs[value.data.procedure->params[i].var_info.id] = LOC_REG(i);
		compiler->var_regs[value.data.procedure->thisproc->id] = compiler->eval_regs[value.id];
		allocate_code_block_regs(compiler, value.data.procedure->exec_block, value.data.procedure->param_count);
		return current_reg;
	}
	case AST_VALUE_VAR:
		compiler->eval_regs[value.id] = compiler->var_regs[value.data.variable->id];
		compiler->move_eval[value.id] = 1;
		return current_reg;
	case AST_VALUE_SET_VAR:
		compiler->eval_regs[value.id] = compiler->var_regs[value.data.set_var->var_info->id];
		allocate_value_regs(compiler, value.data.set_var->set_value, current_reg, &compiler->eval_regs[value.id]);
		compiler->eval_regs[value.id] = compiler->eval_regs[value.data.set_var->set_value.id];
		compiler->move_eval[value.id] = compiler->move_eval[value.data.set_var->set_value.id];
		return current_reg;
	case AST_VALUE_SET_INDEX:
		extra_regs = allocate_value_regs(compiler, value.data.set_index->array, extra_regs, NULL);
		if(value.data.set_index->index.value_type != AST_VALUE_PRIMITIVE)
			extra_regs = allocate_value_regs(compiler, value.data.set_index->index, extra_regs, NULL);
		allocate_value_regs(compiler, value.data.set_index->value, extra_regs, NULL);
		compiler->eval_regs[value.id] = compiler->eval_regs[value.data.set_index->value.id];
		compiler->move_eval[value.id] = compiler->move_eval[value.data.set_index->value.id];
		return current_reg;
	case AST_VALUE_SET_PROP:
		extra_regs = allocate_value_regs(compiler, value.data.set_prop->record, extra_regs, NULL);
		allocate_value_regs(compiler, value.data.set_prop->value, extra_regs, NULL);
		compiler->eval_regs[value.id] = compiler->eval_regs[value.data.set_prop->value.id];
		compiler->move_eval[value.id] = compiler->move_eval[value.data.set_prop->value.id];
		return current_reg;
	case AST_VALUE_GET_INDEX:
		extra_regs = allocate_value_regs(compiler, value.data.get_index->array, extra_regs, NULL);
		if(value.data.set_index->index.value_type != AST_VALUE_PRIMITIVE)
			allocate_value_regs(compiler, value.data.get_index->index, extra_regs, NULL);
		break;
	case AST_VALUE_GET_PROP:
		allocate_value_regs(compiler, value.data.get_prop->record, extra_regs, NULL);
		break;
	case AST_VALUE_BINARY_OP:
		extra_regs = allocate_value_regs(compiler, value.data.binary_op->lhs, extra_regs, NULL);
		allocate_value_regs(compiler, value.data.binary_op->rhs, extra_regs, NULL);
		break;
	case AST_VALUE_UNARY_OP:
		allocate_value_regs(compiler, value.data.unary_op->operand, current_reg, NULL);
		break;
	case AST_VALUE_PROC_CALL: {
		compiler->eval_regs[value.id] = LOC_REG(compiler->proc_call_offsets[value.data.proc_call->id] = extra_regs);
		compiler->move_eval[value.id] = !(value.type.type == TYPE_NOTHING || !target_reg || (target_reg->offset && target_reg->reg == current_reg));
		for (uint_fast8_t i = 0; i < value.data.proc_call->argument_count; i++) {
			compiler_reg_t arg_reg = LOC_REG(extra_regs);
			allocate_value_regs(compiler, value.data.proc_call->arguments[i], extra_regs++, &arg_reg);
		}
		allocate_value_regs(compiler, value.data.proc_call->procedure, extra_regs, NULL);
		return current_reg + 1;
	}
	case AST_VALUE_FOREIGN:
		extra_regs = allocate_value_regs(compiler, value.data.foreign->op_id, extra_regs, NULL);
		if(value.data.foreign->input)
			allocate_value_regs(compiler, *value.data.foreign->input, extra_regs, NULL);
		break;
	}
	if (target_reg) {
		compiler->eval_regs[value.id] = *target_reg;
		compiler->move_eval[value.id] = 0;
	}
	else {
		compiler->eval_regs[value.id] = LOC_REG(current_reg++);
		compiler->move_eval[value.id] = 1;
	}
	return current_reg;
}

static void allocate_code_block_regs(compiler_t* compiler, ast_code_block_t code_block, uint16_t current_reg) {
	for (uint_fast32_t i = 0; i < code_block.instruction_count; i++)
		switch (code_block.instructions[i].type)
		{
		case AST_STATEMENT_DECL_VAR: {
			ast_decl_var_t var_decl = code_block.instructions[i].data.var_decl;
			if (!var_decl.var_info->has_mutated &&
				(var_decl.set_value.value_type == AST_VALUE_PRIMITIVE ||
					var_decl.set_value.value_type == AST_VALUE_PROC ||
					(var_decl.set_value.value_type == AST_VALUE_VAR && !var_decl.set_value.data.variable->has_mutated))) {
				current_reg = allocate_value_regs(compiler, var_decl.set_value, current_reg, NULL);
				compiler->var_regs[var_decl.var_info->id] = compiler->eval_regs[var_decl.set_value.id];
				compiler->move_eval[var_decl.set_value.id] = 0;
			}
			else {
				if (var_decl.var_info->is_global) {
					compiler->var_regs[var_decl.var_info->id] = GLOB_REG(compiler->ast->total_constants + compiler->current_global++);
					allocate_value_regs(compiler, var_decl.set_value, current_reg, &compiler->var_regs[var_decl.var_info->id]);
				}
				else {
					compiler->var_regs[var_decl.var_info->id] = LOC_REG(current_reg);
					allocate_value_regs(compiler, var_decl.set_value, current_reg, &compiler->var_regs[var_decl.var_info->id]);
					current_reg++;
				}
			}
			break;
		}
		case AST_STATEMENT_COND: {
			ast_cond_t* conditional = code_block.instructions[i].data.conditional;
			while (conditional)
			{
				if (conditional->condition)
					allocate_value_regs(compiler, *conditional->condition, current_reg, NULL);
				allocate_code_block_regs(compiler, conditional->exec_block, current_reg);
				conditional = conditional->next_if_false;
			}
			break;
		}
		case AST_STATEMENT_VALUE:
			allocate_value_regs(compiler, code_block.instructions[i].data.value, current_reg, NULL);
			break;
		case AST_STATEMENT_RETURN_VALUE: {
			compiler_reg_t return_reg = LOC_REG(0);
			allocate_value_regs(compiler, code_block.instructions[i].data.value, current_reg, &return_reg);
			break;
		}
	}
}

static int compile_code_block(compiler_t* compiler, ast_code_block_t code_block, ast_proc_t* proc, uint16_t continue_ip, uint16_t* break_jumps, uint8_t* break_jump_top);

static int compile_value(compiler_t* compiler, ast_value_t value, ast_proc_t* proc) {
	switch (value.value_type)
	{
	case AST_VALUE_ALLOC_ARRAY:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.alloc_array->size, proc));
		EMIT_INS(INS3(OP_CODE_HEAP_ALLOC, compiler->eval_regs[value.id], compiler->eval_regs[value.data.alloc_array->size.id], GLOB_REG(IS_REF_TYPE(*value.data.alloc_array->elem_type))));
		break;
	case AST_VALUE_ARRAY_LITERAL:
		EMIT_INS(INS3(OP_CODE_HEAP_ALLOC_I, compiler->eval_regs[value.id], GLOB_REG(value.data.array_literal.element_count), GLOB_REG(IS_REF_TYPE(*value.data.array_literal.elem_type))));
		for (uint_fast32_t i = 0; i < value.data.array_literal.element_count; i++) {
			ESCAPE_ON_FAIL(compile_value(compiler, value.data.array_literal.elements[i], proc));
			EMIT_INS(INS3(OP_CODE_STORE_HEAP_I, compiler->eval_regs[value.id], GLOB_REG(i), compiler->eval_regs[value.data.array_literal.elements[i].id]));
		}
		break;
	case AST_VALUE_ALLOC_RECORD: {
		ast_record_proto_t* current_proto = value.data.alloc_record.proto;
		EMIT_INS(INS3(OP_CODE_HEAP_ALLOC_I, compiler->eval_regs[value.id], GLOB_REG(current_proto->index_offset + current_proto->property_count), GLOB_REG(current_proto->do_gc ? GC_TRACE_SOME : GC_NO_TRACE)));
		do {
			for (uint_fast8_t i = 0; i < current_proto->property_count; i++) {
				for(uint_fast16_t j = 0; j < value.data.alloc_record.init_value_count; j++)
					if (value.data.alloc_record.init_values[j].property == &current_proto->properties[i]) {
						ESCAPE_ON_FAIL(compile_value(compiler, *value.data.alloc_record.init_values[j].value, proc));
						EMIT_INS(INS3(OP_CODE_STORE_HEAP_I, compiler->eval_regs[value.id], GLOB_REG(current_proto->properties[i].id), compiler->eval_regs[value.data.alloc_record.init_values[j].value->id]));
						goto heap_trace;
					}
				if (current_proto->properties[i].default_value) {
					ESCAPE_ON_FAIL(compile_value(compiler, *current_proto->properties[i].default_value, proc));
					EMIT_INS(INS3(OP_CODE_STORE_HEAP_I, compiler->eval_regs[value.id], GLOB_REG(current_proto->properties[i].id), compiler->eval_regs[current_proto->properties[i].default_value->id]));
				}
			heap_trace:
				EMIT_INS(INS3(OP_CODE_HEAP_TRACE_I, compiler->eval_regs[value.id], GLOB_REG(current_proto->properties[i].id), GLOB_REG(IS_REF_TYPE(current_proto->properties[i].type))));
			}
			if (current_proto->base_record)
				current_proto = compiler->ast->record_protos[current_proto->base_record->type_id];
			else
				current_proto = NULL;
		} while (current_proto);
		break;
	}
	case AST_VALUE_PROC: {
		uint16_t start_ip = compiler->ins_builder.instruction_count;
		EMIT_INS(INS1(OP_CODE_LABEL, compiler->eval_regs[value.id]));
		EMIT_INS(INS0(OP_CODE_JUMP));
		compiler->ins_builder.instructions[start_ip].b = compiler->ins_builder.instruction_count;
		if(value.data.procedure->do_gc)
			EMIT_INS(INS0(OP_CODE_HEAP_NEW_FRAME));
		compile_code_block(compiler, value.data.procedure->exec_block, value.data.procedure, 0 , NULL, 0);
		EMIT_INS(INS1(OP_CODE_ABORT, GLOB_REG(0)));
		compiler->ins_builder.instructions[start_ip + 1].a = compiler->ins_builder.instruction_count;
		break;
	}
	case AST_VALUE_SET_VAR:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.set_var->set_value, proc));
		if (compiler->move_eval[value.data.set_var->set_value.id])
			EMIT_INS(INS2(OP_CODE_MOVE, compiler->var_regs[value.data.set_var->var_info->id], compiler->eval_regs[value.data.set_var->set_value.id]));
		if (value.data.set_var->gc_trace && proc->do_gc)
			EMIT_INS(INS1(OP_CODE_HEAP_TRACE, compiler->var_regs[value.data.set_var->var_info->id]));
		break;
	case AST_VALUE_SET_INDEX:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.set_index->array, proc));
		if(value.data.set_index->index.value_type != AST_VALUE_PRIMITIVE)
			ESCAPE_ON_FAIL(compile_value(compiler, value.data.set_index->index, proc));
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.set_index->value, proc));
		if (value.data.set_index->index.value_type == AST_VALUE_PRIMITIVE)
			EMIT_INS(INS3(OP_CODE_STORE_HEAP_I_BOUND, compiler->eval_regs[value.data.set_index->array.id], GLOB_REG(value.data.set_index->index.data.primitive.data.long_int), compiler->eval_regs[value.data.set_index->value.id]))
		else
			EMIT_INS(INS3(OP_CODE_STORE_HEAP, compiler->eval_regs[value.data.set_index->array.id], compiler->eval_regs[value.data.set_index->index.id], compiler->eval_regs[value.data.set_index->value.id]));
		if (value.data.set_index->gc_trace && proc->do_gc)
			EMIT_INS(INS1(OP_CODE_HEAP_TRACE, compiler->eval_regs[value.data.set_index->value.id]));
		break;
	case AST_VALUE_SET_PROP:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.set_prop->record, proc));
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.set_prop->value, proc));
		EMIT_INS(INS3(OP_CODE_STORE_HEAP_I, compiler->eval_regs[value.data.set_prop->record.id], GLOB_REG(value.data.set_prop->property->id), compiler->eval_regs[value.data.set_prop->value.id]));
		if (value.data.set_prop->gc_trace && proc->do_gc)
			EMIT_INS(INS1(OP_CODE_HEAP_TRACE, compiler->eval_regs[value.data.set_prop->value.id]));
		break;
	case AST_VALUE_GET_INDEX:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.get_index->array, proc));
		if(value.data.get_index->index.value_type == AST_VALUE_PRIMITIVE)
			EMIT_INS(INS3(OP_CODE_LOAD_HEAP_I_BOUND, compiler->eval_regs[value.data.get_index->array.id], GLOB_REG(value.data.get_index->index.data.primitive.data.long_int), compiler->eval_regs[value.id]))
		else {
			ESCAPE_ON_FAIL(compile_value(compiler, value.data.get_index->index, proc));
			EMIT_INS(INS3(OP_CODE_LOAD_HEAP, compiler->eval_regs[value.data.get_index->array.id], compiler->eval_regs[value.data.get_index->index.id], compiler->eval_regs[value.id]));
		}
		break;
	case AST_VALUE_GET_PROP:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.get_prop->record, proc));
		EMIT_INS(INS3(OP_CODE_LOAD_HEAP_I, compiler->eval_regs[value.data.get_prop->record.id], GLOB_REG(value.data.get_prop->property->id), compiler->eval_regs[value.id]));
		break;
	case AST_VALUE_BINARY_OP: {
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.binary_op->lhs, proc));
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.binary_op->rhs, proc));
		compiler_reg_t lhs = compiler->eval_regs[value.data.binary_op->lhs.id];
		compiler_reg_t rhs = compiler->eval_regs[value.data.binary_op->rhs.id];
 		if (value.data.binary_op->operator == TOK_EQUALS || value.data.binary_op->operator == TOK_NOT_EQUAL) {
			EMIT_INS(INS3(OP_CODE_BOOL_EQUAL + value.data.binary_op->lhs.type.type - TYPE_PRIMITIVE_BOOL, lhs, rhs, compiler->eval_regs[value.id]));
			if (value.data.binary_op->operator == TOK_NOT_EQUAL)
				EMIT_INS(INS2(OP_CODE_NOT, compiler->eval_regs[value.id], compiler->eval_regs[value.id]));
		}
		else if (value.data.binary_op->operator == TOK_AND || value.data.binary_op->operator == TOK_OR)
			EMIT_INS(INS3(OP_CODE_AND + value.data.binary_op->operator - TOK_AND, rhs, lhs, compiler->eval_regs[value.id]))
		else {
			if (value.data.binary_op->lhs.type.type == TYPE_PRIMITIVE_LONG)
				EMIT_INS(INS3(OP_CODE_LONG_MORE + (value.data.binary_op->operator - TOK_MORE), lhs, rhs, compiler->eval_regs[value.id]))
			else
				EMIT_INS(INS3(OP_CODE_FLOAT_MORE + (value.data.binary_op->operator - TOK_MORE), lhs, rhs, compiler->eval_regs[value.id]))
		}
		break;
	}
	case AST_VALUE_UNARY_OP:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.unary_op->operand, proc));
		if (value.data.unary_op->operator == TOK_SUBTRACT)
			EMIT_INS(INS2(OP_CODE_LONG_NEGATE + value.type.type - TYPE_PRIMITIVE_LONG, compiler->eval_regs[value.id], compiler->eval_regs[value.data.unary_op->operand.id]))
		else
			EMIT_INS(INS2(OP_CODE_NOT + value.data.unary_op->operator - TOK_NOT, compiler->eval_regs[value.id], compiler->eval_regs[value.data.unary_op->operand.id]))
		break;
	case AST_VALUE_PROC_CALL: {
		for (uint_fast8_t i = 0; i < value.data.proc_call->argument_count; i++) {
			ESCAPE_ON_FAIL(compile_value(compiler, value.data.proc_call->arguments[i], proc));
			if (compiler->move_eval[value.data.proc_call->arguments[i].id])
				EMIT_INS(INS2(OP_CODE_MOVE, LOC_REG(compiler->proc_call_offsets[value.data.proc_call->id] + i), compiler->eval_regs[value.data.proc_call->arguments[i].id]));
		}
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.proc_call->procedure, proc));
		EMIT_INS(INS2(OP_CODE_CALL, compiler->eval_regs[value.data.proc_call->procedure.id], GLOB_REG(compiler->proc_call_offsets[value.data.proc_call->id])));
		if (compiler->proc_call_offsets[value.data.proc_call->id])
			EMIT_INS(INS1(OP_CODE_STACK_DEOFFSET, GLOB_REG(compiler->proc_call_offsets[value.data.proc_call->id])));
		break; 
	}
	case AST_VALUE_FOREIGN:
		ESCAPE_ON_FAIL(compile_value(compiler, value.data.foreign->op_id, proc));
		if (value.data.foreign->input) {
			ESCAPE_ON_FAIL(compile_value(compiler, *value.data.foreign->input, proc));
			EMIT_INS(INS3(OP_CODE_FOREIGN, compiler->eval_regs[value.data.foreign->op_id.id], compiler->eval_regs[value.data.foreign->input->id], compiler->eval_regs[value.id]));
		}
		else
			EMIT_INS(INS3(OP_CODE_FOREIGN, compiler->eval_regs[value.data.foreign->op_id.id], LOC_REG(0), compiler->eval_regs[value.id]));
	}
	return 1;
}

static int compile_conditional(compiler_t* compiler, ast_cond_t* conditional, ast_proc_t* proc, uint16_t continue_ip, uint16_t* break_jumps, uint8_t* break_jump_top) {
	if (conditional->next_if_true) {
		uint16_t this_continue_ip = compiler->ins_builder.instruction_count;
		ESCAPE_ON_FAIL(compile_value(compiler, *conditional->condition, proc));
		uint16_t this_break_ip = compiler->ins_builder.instruction_count;

		static uint16_t lp_break_jumps[64];
		uint8_t lp_break_jump_count = 0;

		EMIT_INS(INS1(OP_CODE_JUMP_CHECK, compiler->eval_regs[conditional->condition->id]));
		ESCAPE_ON_FAIL(compile_code_block(compiler, conditional->exec_block, proc, this_continue_ip, lp_break_jumps, &lp_break_jump_count));
		EMIT_INS(INS1(OP_CODE_JUMP, GLOB_REG(this_continue_ip)));
		compiler->ins_builder.instructions[this_break_ip].b = compiler->ins_builder.instruction_count;
		for (uint_fast8_t i = 0; i < lp_break_jump_count; i++)
			compiler->ins_builder.instructions[lp_break_jumps[i]].a = compiler->ins_builder.instruction_count;
	}
	else {
		uint16_t escape_jump_count = 0;
		ast_cond_t* count_cond = conditional;
		while (count_cond) {
			if (count_cond->condition)
				escape_jump_count++;
			count_cond = count_cond->next_if_false;
		}
		//escape_jump_count--;
		uint16_t* escape_jumps = malloc(escape_jump_count * sizeof(uint16_t));
		PANIC_ON_FAIL(escape_jumps, compiler, ERROR_MEMORY);
		uint16_t current_escape_jump = 0;
		while (conditional) {
			if (conditional->condition) {
				ESCAPE_ON_FAIL(compile_value(compiler, *conditional->condition, proc));
				uint16_t move_next_ip = compiler->ins_builder.instruction_count;
				EMIT_INS(INS1(OP_CODE_JUMP_CHECK, compiler->eval_regs[conditional->condition->id]));
				ESCAPE_ON_FAIL(compile_code_block(compiler, conditional->exec_block, proc, continue_ip, break_jumps, break_jump_top));
				if (current_escape_jump != escape_jump_count) {
					escape_jumps[current_escape_jump++] = compiler->ins_builder.instruction_count;
					EMIT_INS(INS0(OP_CODE_JUMP));
				}
				compiler->ins_builder.instructions[move_next_ip].b = compiler->ins_builder.instruction_count;
			}
			else
				ESCAPE_ON_FAIL(compile_code_block(compiler, conditional->exec_block, proc, continue_ip, break_jumps, break_jump_top));
			conditional = conditional->next_if_false;
		}
		for (uint_fast16_t i = 0; i < escape_jump_count; i++)
			compiler->ins_builder.instructions[escape_jumps[i]].a = compiler->ins_builder.instruction_count;
		free(escape_jumps);
	}
	return 1;
}

static int compile_code_block(compiler_t* compiler, ast_code_block_t code_block, ast_proc_t* proc, uint16_t continue_ip, uint16_t* break_jumps, uint8_t* break_jump_top) {
	for (uint_fast32_t i = 0; i < code_block.instruction_count; i++)
		switch (code_block.instructions[i].type) {
		case AST_STATEMENT_DECL_VAR:
			ESCAPE_ON_FAIL(compile_value(compiler, code_block.instructions[i].data.var_decl.set_value, proc));
			if (compiler->move_eval[code_block.instructions[i].data.var_decl.set_value.id])
				EMIT_INS(INS2(OP_CODE_MOVE, compiler->var_regs[code_block.instructions[i].data.var_decl.var_info->id], compiler->eval_regs[code_block.instructions[i].data.var_decl.set_value.id]));
			break;
		case AST_STATEMENT_COND:
			ESCAPE_ON_FAIL(compile_conditional(compiler, code_block.instructions[i].data.conditional, proc, continue_ip, break_jumps, break_jump_top));
			break;
		case AST_STATEMENT_VALUE:
			ESCAPE_ON_FAIL(compile_value(compiler, code_block.instructions[i].data.value, proc));
			break;
		case AST_STATEMENT_RETURN_VALUE: {
			ESCAPE_ON_FAIL(compile_value(compiler, code_block.instructions[i].data.value, proc));
			compiler_reg_t src_reg = compiler->eval_regs[code_block.instructions[i].data.value.id];
			if (compiler->move_eval[code_block.instructions[i].data.value.id] && !(!src_reg.reg && src_reg.offset))
				EMIT_INS(INS2(OP_CODE_MOVE, LOC_REG(0), src_reg));
			if (code_block.instructions[i].data.value.gc_status == GC_LOCAL_ALLOC && proc->do_gc)
				EMIT_INS(INS1(OP_CODE_HEAP_TRACE, LOC_REG(0))); 
		}
		case AST_STATEMENT_RETURN:
			if(proc->do_gc)
				EMIT_INS(INS0(OP_CODE_HEAP_CLEAN));
			EMIT_INS(INS0(OP_CODE_RETURN));
			break;
		case AST_STATEMENT_BREAK:
			if (*break_jump_top == 64)
				PANIC(compiler, ERROR_INTERNAL);
			break_jumps[(*break_jump_top)++] = compiler->ins_builder.instruction_count;
			EMIT_INS(INS1(OP_CODE_JUMP, GLOB_REG(0)));
			break;
		case AST_STATEMENT_CONTINUE:
			EMIT_INS(INS1(OP_CODE_JUMP, GLOB_REG(continue_ip)));
			break;
		}
	return 1;
}

int compile(compiler_t* compiler, machine_t* target_machine, ast_t* ast) {
	compiler->target_machine = target_machine;
	compiler->ast = ast;
	compiler->last_err = ERROR_NONE;
	compiler->current_constant = 0;
	compiler->current_global = 0;
	
	PANIC_ON_FAIL(compiler->eval_regs = malloc(ast->value_count * sizeof(compiler_reg_t)), compiler, ERROR_MEMORY);
	PANIC_ON_FAIL(compiler->move_eval = malloc(ast->value_count * sizeof(int)), compiler, ERROR_MEMORY);
	PANIC_ON_FAIL(compiler->var_regs = malloc(ast->total_var_decls * sizeof(compiler_reg_t)), compiler, ERROR_MEMORY);
	PANIC_ON_FAIL(compiler->proc_call_offsets = malloc(ast->proc_call_count * sizeof(uint16_t)), compiler, ERROR_MEMORY);

	PANIC_ON_FAIL(init_machine(target_machine, UINT16_MAX, 1000, 1000), compiler, target_machine->last_err);
	allocate_code_block_regs(compiler, ast->exec_block, 0);

	PANIC_ON_FAIL(init_ins_builder(&compiler->ins_builder), compiler, ERROR_MEMORY);
	
	EMIT_INS(INS1(OP_CODE_STACK_OFFSET, GLOB_REG(compiler->ast->total_constants + compiler->current_global)));
	EMIT_INS(INS0(OP_CODE_HEAP_NEW_FRAME));
	ESCAPE_ON_FAIL(compile_code_block(compiler, ast->exec_block, NULL, 0, NULL, 0));
	EMIT_INS(INS0(OP_CODE_HEAP_CLEAN));
	EMIT_INS(INS1(OP_CODE_ABORT, GLOB_REG(1)));

	free(compiler->eval_regs);
	free(compiler->move_eval);
	free(compiler->var_regs);
	free(compiler->proc_call_offsets);

	return 1;
}