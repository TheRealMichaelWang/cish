#pragma once

#ifndef TYPE_H
#define TYPE_H

#include <stdint.h>

#define TYPE_MAX_SUBTYPES 100

typedef struct typecheck_type typecheck_type_t;
typedef struct ast ast_t;

typedef enum typecheck_base_type {
	TYPE_AUTO,
	TYPE_NOTHING,
	TYPE_ANY,
	TYPE_TYPEARG,

	TYPE_PRIMITIVE_BOOL,
	TYPE_PRIMITIVE_CHAR,
	TYPE_PRIMITIVE_LONG,
	TYPE_PRIMITIVE_FLOAT,

	TYPE_SUPER_ARRAY,
	TYPE_SUPER_PROC,
	TYPE_SUPER_RECORD
} typecheck_base_type_t;

typedef struct typecheck_type {
	typecheck_base_type_t type;
	typecheck_type_t* sub_types;
	uint8_t sub_type_count;
	uint8_t type_id;
} typecheck_type_t;

#define IS_REF_TYPE(TYPE) ((TYPE).type == TYPE_SUPER_ARRAY || (TYPE).type == TYPE_SUPER_RECORD)
#define IS_PRIMITIVE(TYPE) ((TYPE).type >= TYPE_PRIMITIVE_BOOL && (TYPE).type <= TYPE_PRIMITIVE_FLOAT)

static typecheck_type_t typecheck_int = { .type = TYPE_PRIMITIVE_LONG };
static typecheck_type_t typecheck_float = { .type = TYPE_PRIMITIVE_FLOAT };
static typecheck_type_t typecheck_char = { .type = TYPE_PRIMITIVE_CHAR };
static typecheck_type_t typecheck_bool = { .type = TYPE_PRIMITIVE_BOOL };
static typecheck_type_t typecheck_array = { .type = TYPE_SUPER_ARRAY };
static typecheck_type_t typecheck_any = { .type = TYPE_ANY };

void free_typecheck_type(typecheck_type_t* typecheck_type);
int copy_typecheck_type(typecheck_type_t* dest, typecheck_type_t src);

int typecheck_compatible(ast_t* ast, typecheck_type_t* target_type, typecheck_type_t match_type);

int typecheck_has_type(typecheck_type_t type, typecheck_base_type_t base_type);

int typeargs_substitute(typecheck_type_t* input_typeargs, typecheck_type_t* proto_type);
int typecheck_lowest_common_type(ast_t* ast, typecheck_type_t a, typecheck_type_t b, typecheck_type_t* result);
#endif // !TYPE