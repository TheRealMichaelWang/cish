#include <stdlib.h>
#include "compiler.h"

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif // !max

#define TEMPREG(INDEX) (ast_reg_t){.index = INDEX, .offset_flag = 1}
#define GLOBREG(INDEX) (ast_reg_t){.index = INDEX, .offset_flag = 0}

#define INS0(OP) (machine_ins_t) {.op_code = OP}
#define INS1(OP, REGA) (machine_ins_t){.op_code = OP, .a = REGA.index, .a_flag = REGA.offset_flag}
#define INS2(OP, REGA, REGB) (machine_ins_t){.op_code = OP, .a = REGA.index, .a_flag = REGA.offset_flag, .b = REGB.index, .b_flag = REGB.offset_flag}
#define INS3(OP, REGA, REGB, REGC) (machine_ins_t){.op_code = OP, .a = REGA.index, .a_flag = REGA.offset_flag, .b = REGB.index, .b_flag = REGB.offset_flag, .c = REGC.index, .c_flag = REGC.offset_flag}

#define PUSH_INS(INS) PANIC_ON_NULL(ins_builder_append_ins(ins_builder, INS), compiler, ERROR_MEMORY)

#define ALLOC_REG {ast_value->alloced_reg.index = (*current_prim_reg)++; ast_value->alloced_reg.offset_flag = 0; break; }

static void alloc_ast_code_block(compiler_t* compiler, machine_t* machine, ast_code_block_t* code_block, uint16_t* current_prim_reg);
static const int compile_code_block(compiler_t* compiler, ins_builder_t* ins_builder, ast_code_block_t* code_block, uint16_t temp_regs, ast_proc_t* procedure, uint16_t break_jump, uint16_t continue_jump);
static const int compile_ast_value(compiler_t* compiler, ins_builder_t* ins_builder, ast_value_t* value, ast_reg_t out_reg, uint16_t temp_regs);

const int init_ins_builder(ins_builder_t* ins_builder) {
	ESCAPE_ON_NULL(ins_builder->instructions = malloc((ins_builder->alloced_ins = 64) * sizeof(machine_ins_t)));
	ins_builder->instruction_count = 0;
	return 1;
}

const int ins_builder_append_ins(ins_builder_t* ins_builder, machine_ins_t ins) {
	if (ins_builder->instruction_count == ins_builder->alloced_ins) {
		machine_ins_t* new_ins = realloc(ins_builder->instructions, (ins_builder->alloced_ins *= 2) * sizeof(machine_ins_t));
		ESCAPE_ON_NULL(new_ins);
		ins_builder->instructions = new_ins;
	}
	ins_builder->instructions[ins_builder->instruction_count++] = ins;
	return 1;
}

static void alloc_ast_prim(compiler_t* compiler, machine_t* machine, ast_value_t* ast_value, uint16_t* current_prim_reg) {
	switch (ast_value->value_type)
	{
	case AST_VALUE_BOOL:
		machine->stack[*current_prim_reg].bool_flag = ast_value->data.bool_flag;
		ALLOC_REG;
	case AST_VALUE_CHAR:
		machine->stack[*current_prim_reg].char_int = ast_value->data.character;
		ALLOC_REG;
	case AST_VALUE_LONG:
		machine->stack[*current_prim_reg].long_int = ast_value->data.long_int;
		ALLOC_REG;
	case AST_VALUE_FLOAT:
		machine->stack[*current_prim_reg].float_int = ast_value->data.float_int;
		ALLOC_REG;
	case AST_VALUE_ALLOC_ARRAY:
		alloc_ast_prim(compiler, machine, &ast_value->data.alloc_array->size, current_prim_reg);
		break;
	case AST_VALUE_ARRAY_LITERAL: {
		for (uint_fast32_t i = 0; i < ast_value->data.array_literal.element_count; i++)
			alloc_ast_prim(compiler, machine, &ast_value->data.array_literal.elements[i], current_prim_reg);
		break;
	case AST_VALUE_GET_INDEX:
		alloc_ast_prim(compiler, machine, &ast_value->data.get_index->array, current_prim_reg);
		alloc_ast_prim(compiler, machine, &ast_value->data.get_index->index, current_prim_reg);
		break;
	case AST_VALUE_SET_VAR:
		alloc_ast_prim(compiler, machine, &ast_value->data.set_var->set_value, current_prim_reg);
		break;
	case AST_VALUE_SET_INDEX:
		alloc_ast_prim(compiler, machine, &ast_value->data.set_index->array, current_prim_reg);
		alloc_ast_prim(compiler, machine, &ast_value->data.set_index->index, current_prim_reg);
		alloc_ast_prim(compiler, machine, &ast_value->data.set_index->value, current_prim_reg);
		break;
	case AST_VALUE_BINARY_OP:
		alloc_ast_prim(compiler, machine, &ast_value->data.binary_op->lhs, current_prim_reg);
		alloc_ast_prim(compiler, machine, &ast_value->data.binary_op->rhs, current_prim_reg);
		break;
	case AST_VALUE_UNARY_OP:
		alloc_ast_prim(compiler, machine, &ast_value->data.unary_op->operand, current_prim_reg);
		break;
	case AST_VALUE_PROC_CALL:
		for (uint_fast8_t i = 0; i < ast_value->data.proc_call->argument_count; i++)
			alloc_ast_prim(compiler, machine, &ast_value->data.proc_call->arguments[i], current_prim_reg);
		break;
	case AST_VALUE_PROC: {
		alloc_ast_code_block(compiler, machine, &ast_value->data.procedure->exec_block, current_prim_reg);
		break;}
	}
	}
}

static void alloc_ast_code_block(compiler_t* compiler, machine_t* machine, ast_code_block_t* code_block, uint16_t* current_prim_reg) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++) {
		switch (code_block->instructions[i].type)
		{
		case AST_TOP_LEVEL_DECL_VAR:
			alloc_ast_prim(compiler, machine, &code_block->instructions[i].data.var_decl.set_value, current_prim_reg);
			break; 
		case AST_TOP_LEVEL_COND: {
			ast_cond_t* current_conditional = code_block->instructions[i].data.conditional;
			while (current_conditional) {
				alloc_ast_prim(compiler, machine, &current_conditional->cond_val, current_prim_reg);
				alloc_ast_code_block(compiler, machine, &current_conditional->exec_block, current_prim_reg);
				if (current_conditional->next_if_false)
					current_conditional = current_conditional->next_if_false;
				else if (current_conditional != current_conditional->next_if_true)
					current_conditional = current_conditional->next_if_true;
				else
					break;
			}
			break;
		}
		case AST_TOP_LEVEL_RETURN_VALUE:
		case AST_TOP_LEVEL_VALUE:
			alloc_ast_prim(compiler, machine, &code_block->instructions[i].data.value, current_prim_reg);
			break;
		case AST_TOP_LEVEL_FOREIGN: {
			alloc_ast_prim(compiler, machine, &code_block->instructions[i].data.foreign.id_t, current_prim_reg); 
			if (code_block->instructions[i].data.foreign.has_input)
				alloc_ast_prim(compiler, machine, &code_block->instructions[i].data.foreign.input, current_prim_reg);
			break;
		}
		}
	}
}

const int init_compiler(compiler_t* compiler, const char* source) {
	compiler->last_err = ERROR_NONE;
	PANIC_ON_NULL(init_ast(&compiler->ast, source), compiler, compiler->ast.last_err);
	return 1;
}

void free_compiler(compiler_t* compiler) {
	free_ast(&compiler->ast);
}

static const int compile_ast_proc(compiler_t* compiler, ins_builder_t* ins_builder, ast_proc_t* procedure, ast_reg_t out_reg) {
	uint16_t label_ins_ip = ins_builder->instruction_count;
	PUSH_INS(INS2(OP_CODE_LABEL, out_reg, GLOBREG(0)));
	uint16_t jump_ins_ip = ins_builder->instruction_count;
	PUSH_INS(INS1(OP_CODE_JUMP, GLOBREG(0))); 
	ins_builder->instructions[label_ins_ip].b = ins_builder->instruction_count;
	PUSH_INS(INS0(OP_CODE_HEAP_NEW_FRAME));
	ESCAPE_ON_NULL(compile_code_block(compiler, ins_builder, &procedure->exec_block, procedure->exec_block.register_limit, procedure, 0, 0));
	PUSH_INS(INS0(OP_CODE_ABORT)); //instead of checking all code-paths for return statments, this aborts instead
	ins_builder->instructions[jump_ins_ip].a = ins_builder->instruction_count;
	return 1;
}

static const int compile_ast_value_reg(compiler_t* compiler, ins_builder_t* ins_builder, ast_value_t* value, ast_reg_t* dest_reg, ast_reg_t set_regs, uint16_t temp_regs) {
	switch (value->value_type)
	{
	case AST_VALUE_SET_VAR: {
		ESCAPE_ON_NULL(compile_ast_value(compiler, ins_builder, &value->data.set_var->set_value, value->alloced_reg, temp_regs));
		if (value->data.set_var->set_global && value->type.type == TYPE_SUPER_ARRAY)
			PUSH_INS(INS1(OP_CODE_HEAP_TRACE, value->alloced_reg));
	}
	case AST_VALUE_BOOL:
	case AST_VALUE_CHAR:
	case AST_VALUE_LONG:
	case AST_VALUE_FLOAT:
	case AST_VALUE_VAR:
		*dest_reg = value->alloced_reg;
		break;
	case AST_VALUE_PROC_CALL: {
		ast_reg_t proc_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.proc_call->procedure, &proc_reg, TEMPREG(temp_regs), temp_regs));
		for (uint8_t i = 0; i < value->data.proc_call->argument_count; i++)
			ESCAPE_ON_NULL(compile_ast_value(compiler, ins_builder, &value->data.proc_call->arguments[i], TEMPREG(temp_regs + i + 1), temp_regs + i + 2));
		PUSH_INS(INS2(OP_CODE_MOVE, TEMPREG(temp_regs + value->data.proc_call->argument_count + 1), proc_reg));
		PUSH_INS(INS1(OP_CODE_STACK_OFFSET, GLOBREG(temp_regs)));
		PUSH_INS(INS1(OP_CODE_JUMP_HIST, TEMPREG(value->data.proc_call->argument_count + 1)));
		PUSH_INS(INS1(OP_CODE_STACK_DEOFFSET, GLOBREG(temp_regs)));
		*dest_reg = TEMPREG(temp_regs);
		break;
	}
	default:
		compile_ast_value(compiler, ins_builder, value, set_regs, temp_regs);
		*dest_reg = set_regs;
		break;
	}
	return 1;
};

static const int compile_ast_value(compiler_t* compiler, ins_builder_t* ins_builder, ast_value_t* value, ast_reg_t out_reg, uint16_t temp_regs) {
	switch (value->value_type)
	{
	case AST_VALUE_SET_VAR:
	case AST_VALUE_BOOL:
	case AST_VALUE_CHAR:
	case AST_VALUE_LONG:
	case AST_VALUE_FLOAT:
	case AST_VALUE_VAR:
	case AST_VALUE_PROC_CALL: {
		ast_reg_t reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, value, &reg, out_reg, temp_regs));
		PUSH_INS(INS2(OP_CODE_MOVE, out_reg, reg));
		break; 
	}
	case AST_VALUE_ALLOC_ARRAY: {
		ast_reg_t len_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.alloc_array->size, &len_reg, out_reg, temp_regs));
		PUSH_INS(INS3(OP_CODE_HEAP_ALLOC, out_reg, len_reg, GLOBREG(value->data.alloc_array->elem_type.type == TYPE_SUPER_ARRAY)));
		break;
	}
	case AST_VALUE_ARRAY_LITERAL: {
		PUSH_INS(INS3(OP_CODE_HEAP_ALLOC_I, out_reg, GLOBREG(value->data.array_literal.element_count), GLOBREG(value->data.array_literal.elem_type.type == TYPE_SUPER_ARRAY)));
		for (uint_fast32_t i = 0; i < value->data.array_literal.element_count; i++) {
			ast_reg_t elem_reg;
			ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.array_literal.elements[i], &elem_reg, TEMPREG(temp_regs), temp_regs + 1));
			PUSH_INS(INS3(OP_CODE_STORE_HEAP_I, out_reg, GLOBREG(i), elem_reg));
		}
		break;
	}
	case AST_VALUE_PROC:
		ESCAPE_ON_NULL(compile_ast_proc(compiler, ins_builder, value->data.procedure, out_reg));
		break;
	case AST_VALUE_GET_INDEX: {
		ast_reg_t array_reg, index_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.get_index->array, &array_reg, out_reg, temp_regs));
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.get_index->index, &index_reg, TEMPREG(temp_regs), temp_regs + 1));
		PUSH_INS(INS3(OP_CODE_LOAD_HEAP, array_reg, index_reg, out_reg));
		break; 
	}
	case AST_VALUE_SET_INDEX: {
		ast_reg_t array_reg, index_reg, value_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.set_index->array, &array_reg, TEMPREG(temp_regs), temp_regs + 1));
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.set_index->index, &index_reg, TEMPREG(temp_regs + 1), temp_regs + 2));
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.set_index->value, &value_reg, out_reg, temp_regs + 2));
		PUSH_INS(INS3(OP_CODE_STORE_HEAP, array_reg, index_reg, value_reg));
		break; 
	}
	case AST_VALUE_BINARY_OP: {
		ast_reg_t lhs_reg, rhs_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.binary_op->lhs, &lhs_reg, out_reg, temp_regs));
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.binary_op->rhs, &rhs_reg, TEMPREG(temp_regs), temp_regs + 1));

		enum typecheck_type_type target_type = max(value->data.binary_op->lhs.type.type, value->data.binary_op->rhs.type.type);
		if (value->data.binary_op->lhs.type.type != target_type) {
			PUSH_INS(INS2(OP_CODE_LONG_TO_FLOAT, lhs_reg, out_reg));
			lhs_reg = out_reg;
		}
		else if (value->data.binary_op->rhs.type.type != target_type) {
			PUSH_INS(INS2(OP_CODE_LONG_TO_FLOAT, rhs_reg, TEMPREG(temp_regs)));
			rhs_reg = TEMPREG(temp_regs);
		}
		if (value->data.binary_op->operator == TOK_EQUALS || value->data.binary_op->operator == TOK_NOT_EQUAL) {
			PUSH_INS(INS3(OP_CODE_BOOL_EQUAL + (target_type - TYPE_PRIMATIVE_BOOL), lhs_reg, rhs_reg, out_reg));
			if (value->data.binary_op->operator == TOK_NOT_EQUAL)
				PUSH_INS(INS2(OP_CODE_NOT, out_reg, out_reg));
		}
		else if (value->data.binary_op->operator == TOK_AND)
			PUSH_INS(INS3(OP_CODE_AND, lhs_reg, rhs_reg, out_reg))
		else if (value->data.binary_op->operator == TOK_OR)
			PUSH_INS(INS3(OP_CODE_OR, lhs_reg, rhs_reg, out_reg))
		else {
			if (target_type == TYPE_PRIMATIVE_LONG)
				PUSH_INS(INS3(OP_CODE_LONG_MORE + (value->data.binary_op->operator - TOK_MORE), lhs_reg, rhs_reg, out_reg))
			else if (target_type == TYPE_PRIMATIVE_FLOAT)
				PUSH_INS(INS3(OP_CODE_FLOAT_MORE + (value->data.binary_op->operator - TOK_MORE), lhs_reg, rhs_reg, out_reg))
			else
				PANIC(compiler, ERROR_UNEXPECTED_TYPE);
		}
		break;
	}
	case AST_VALUE_UNARY_OP: {
		ast_reg_t op_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &value->data.unary_op->operand, &op_reg, out_reg, temp_regs));

		if (value->data.unary_op->operator == TOK_NOT)
			PUSH_INS(INS2(OP_CODE_NOT, op_reg, out_reg))
		else if (value->data.unary_op->operator == TOK_HASHTAG)
			PUSH_INS(INS2(OP_CODE_LENGTH, op_reg, out_reg))
		else {
			if (value->type.type == TOK_TYPECHECK_LONG)
				PUSH_INS(INS2(OP_CODE_LONG_NEGATE, op_reg, out_reg))
			else
				PUSH_INS(INS2(OP_CODE_FLOAT_NEGATE, op_reg, out_reg))
		}
		break;
	}
	}
	return 1;
}

static const int compile_conditional(compiler_t* compiler, ins_builder_t* ins_builder, ast_cond_t* conditional, uint16_t temp_regs, ast_proc_t* procedure, uint16_t break_jump, uint16_t continue_jump) {
	if (conditional->has_cond_val) {
		uint16_t this_begin = ins_builder->instruction_count;
		ast_reg_t cond_reg;
		ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &conditional->cond_val, &cond_reg, TEMPREG(temp_regs), temp_regs + 1));

		PUSH_INS(INS1(OP_CODE_CHECK, cond_reg));
		uint16_t body_jump_ip = ins_builder->instruction_count;

		PUSH_INS(INS1(OP_CODE_JUMP, GLOBREG(0)));
		
		if (conditional->next_if_false) {
			ESCAPE_ON_NULL(compile_code_block(compiler, ins_builder, &conditional->exec_block, temp_regs + 1, procedure, break_jump, continue_jump));
			ins_builder->instructions[body_jump_ip].a = ins_builder->instruction_count;

			PUSH_INS(INS1(OP_CODE_NCHECK, cond_reg));
			uint16_t cond_begin_ip = ins_builder->instruction_count;
			PUSH_INS(INS1(OP_CODE_JUMP, GLOBREG(cond_begin_ip)));
			ESCAPE_ON_NULL(compile_conditional(compiler, ins_builder, conditional->next_if_false, temp_regs, procedure, break_jump, continue_jump));
			ins_builder->instructions[cond_begin_ip].a = ins_builder->instruction_count;
		}
		else {
			if (conditional->next_if_true) {
				ESCAPE_ON_NULL(compile_code_block(compiler, ins_builder, &conditional->exec_block, temp_regs + 1, procedure, body_jump_ip, this_begin))
				PUSH_INS(INS1(OP_CODE_JUMP, GLOBREG(this_begin)));
			}
			else
				ESCAPE_ON_NULL(compile_code_block(compiler, ins_builder, &conditional->exec_block, temp_regs + 1, procedure, break_jump, continue_jump));
			ins_builder->instructions[body_jump_ip].a = ins_builder->instruction_count;
		}
	}
	else
		ESCAPE_ON_NULL(compile_code_block(compiler, ins_builder, &conditional->exec_block, temp_regs + 1, procedure, break_jump, continue_jump));
	return 1;
}

static const int compile_code_block(compiler_t* compiler, ins_builder_t* ins_builder, ast_code_block_t* code_block, uint16_t temp_regs, ast_proc_t* procedure, uint16_t break_jump, uint16_t continue_jump) {
	for (uint_fast32_t i = 0; i < code_block->instruction_count; i++) {
		switch (code_block->instructions[i].type)
		{
		case AST_TOP_LEVEL_DECL_VAR:
			ESCAPE_ON_NULL(compile_ast_value(compiler, ins_builder, &code_block->instructions[i].data.var_decl.set_value, code_block->instructions[i].data.var_decl.var_info.alloced_reg, temp_regs));
			break;
		case AST_TOP_LEVEL_VALUE:
			ESCAPE_ON_NULL(compile_ast_value(compiler, ins_builder, &code_block->instructions[i].data.value, TEMPREG(temp_regs), temp_regs + 1));
			break;
		case AST_TOP_LEVEL_COND:
			ESCAPE_ON_NULL(compile_conditional(compiler, ins_builder, code_block->instructions[i].data.conditional, temp_regs, procedure, break_jump, continue_jump));
			break;
		case AST_TOP_LEVEL_RETURN_VALUE: {
			ESCAPE_ON_NULL(compile_ast_value(compiler, ins_builder, &code_block->instructions[i].data.value, TEMPREG(0), temp_regs));
			if (procedure->return_type.type == TYPE_SUPER_ARRAY)
				PUSH_INS(INS1(OP_CODE_HEAP_TRACE, TEMPREG(0)));
		}
		case AST_TOP_LEVEL_RETURN: {
			for (uint_fast8_t i = 0; i < procedure->param_count; i++)
				if (procedure->params[i].var_info.type.type == TYPE_SUPER_ARRAY)
					PUSH_INS(INS1(OP_CODE_HEAP_TRACE, procedure->params[i].var_info.alloced_reg));
			PUSH_INS(INS0(OP_CODE_HEAP_CLEAN));
			PUSH_INS(INS0(OP_CODE_JUMP_BACK));
			break;
		}
		case AST_TOP_LEVEL_BREAK:
			PANIC_ON_NULL(break_jump, compiler, ERROR_CANNOT_BREAK);
			PUSH_INS(INS1(OP_CODE_JUMP, GLOBREG(break_jump)));
			break;
		case AST_TOP_LEVEL_CONTINUE:
			PANIC_ON_NULL(continue_jump, compiler, ERROR_CANNOT_CONTINUE);
			PUSH_INS(INS1(OP_CODE_JUMP, GLOBREG(continue_jump)));
			break;
		case AST_TOP_LEVEL_FOREIGN: {
			ast_reg_t id_reg;
			ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &code_block->instructions[i].data.foreign.id_t, &id_reg, TEMPREG(temp_regs), temp_regs + 1));

			if (code_block->instructions[i].data.foreign.has_input) {
				ast_reg_t op_reg;
				ESCAPE_ON_NULL(compile_ast_value_reg(compiler, ins_builder, &code_block->instructions[i].data.foreign.input, &op_reg, TEMPREG(temp_regs + 1), temp_regs + 2));
				PUSH_INS(INS3(OP_CODE_FOREIGN, id_reg, op_reg, (code_block->instructions[i].data.foreign.has_output ? code_block->instructions[i].data.foreign.output : GLOBREG(UINT16_MAX))));
			}
			else
				PUSH_INS(INS3(OP_CODE_FOREIGN, TEMPREG(temp_regs), GLOBREG(UINT16_MAX), GLOBREG(UINT16_MAX)));
			break;
		}
		}
	}
	return 1;
}

const int compile(compiler_t* compiler, machine_t* machine, machine_ins_t** output_ins, uint16_t* output_count) {
	PANIC_ON_NULL(init_machine(machine, UINT16_MAX, 1000, 1000), compiler, ERROR_MEMORY);

	uint16_t initial_offset = compiler->allocated_globals = compiler->ast.global_registers;
	alloc_ast_code_block(compiler, machine, &compiler->ast.exec_block, &initial_offset);
	compiler->allocated_constants = initial_offset - compiler->allocated_globals;

	ins_builder_t ins_builder;
	PANIC_ON_NULL(init_ins_builder(&ins_builder), compiler, ERROR_MEMORY);

	ins_builder_append_ins(&ins_builder, (machine_ins_t) { .op_code = OP_CODE_STACK_OFFSET, .a = initial_offset, .a_flag = 0 });
	ins_builder_append_ins(&ins_builder, (machine_ins_t) { .op_code = OP_CODE_HEAP_NEW_FRAME });
	ESCAPE_ON_NULL(compile_code_block(compiler, &ins_builder, &compiler->ast.exec_block, compiler->ast.exec_block.register_limit, NULL, 0, 0));
	ins_builder_append_ins(&ins_builder, (machine_ins_t) { .op_code = OP_CODE_HEAP_CLEAN });

	*output_ins = ins_builder.instructions;
	*output_count = ins_builder.instruction_count;
	return 1;
}