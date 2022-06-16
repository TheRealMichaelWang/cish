#pragma once

#ifndef LABELS_H
#define LABELS_H

#include <stdint.h>
#include "compiler.h"

typedef struct label_buf {
	uint16_t total_labels;
	uint16_t* ins_label;
} label_buf_t;

int init_label_buf(label_buf_t* label_buf, safe_gc_t* safe_gc, compiler_ins_t* compiler_ins, uint64_t instruction_count);

#endif // !LABELS_H
