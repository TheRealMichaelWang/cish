#include "labels.h"

#define LABEL_IP(IP) label_buf->ins_label[IP] = ++label_buf->total_labels;
int init_label_buf(label_buf_t* label_buf, safe_gc_t* safe_gc, compiler_ins_t* compiler_ins, uint64_t instruction_count) {
	ESCAPE_ON_FAIL(label_buf->ins_label = safe_calloc(safe_gc, instruction_count, sizeof(uint16_t)));
	label_buf->total_labels = 0;

	for (uint_fast64_t i = 0; i < instruction_count; i++) {
		switch (compiler_ins[i].op_code) {
		case COMPILER_OP_CODE_JUMP:
			LABEL_IP(compiler_ins[i].regs[0].reg);
			break;
		case COMPILER_OP_CODE_LABEL:
		case COMPILER_OP_CODE_JUMP_CHECK:
			LABEL_IP(compiler_ins[i].regs[1].reg);
			break;
		case COMPILER_OP_CODE_CALL:
			LABEL_IP(i + 1);
			break;
		}
	}
	
	return 1;
}
#undef LABEL_IP