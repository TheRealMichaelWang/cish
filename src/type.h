#pragma once

#ifndef TYPE_H
#define TYPE_H

#include <stdint.h>

#define TYPE_MAX_SUBTYPES 100

typedef struct typecheck_type typecheck_type_t;

typedef struct typecheck_type {
	enum typecheck_type_type {
		TYPE_AUTO,
		TYPE_TYPEARG,
		TYPE_NOTHING,

		TYPE_PRIMATIVE_BOOL,
		TYPE_PRIMATIVE_CHAR,
		TYPE_PRIMATIVE_LONG,
		TYPE_PRIMATIVE_FLOAT,
		
		TYPE_SUPER_ARRAY,
		TYPE_SUPER_PROC,
	} type;

	typecheck_type_t* sub_types;
	uint8_t sub_type_count, match;
} typecheck_type_t;

typedef struct type_matcher {
	typecheck_type_t out_type;

	int* match_flags;
	typecheck_type_t* match_types;
} type_matcher_t;

void free_typecheck_type(typecheck_type_t* typecheck_type);
const int copy_typecheck_type(typecheck_type_t* dest, typecheck_type_t src);

const int typecheck_type_compatible(typecheck_type_t target_type, typecheck_type_t match_type);

const int init_type_matcher(type_matcher_t* type_matcher, typecheck_type_t param_type);
void free_type_matcher(type_matcher_t* type_matcher);

const int type_matcher_add(type_matcher_t* matcher, typecheck_type_t* param, typecheck_type_t arg);
const int type_matcher_finalize(type_matcher_t* type_matcher);

#endif // !TYPE