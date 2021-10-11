#include <stdlib.h>
#include "error.h"
#include "type.h"

void free_typecheck_type(typecheck_type_t* typecheck_type) {
	for (uint_fast8_t i = 0; i < typecheck_type->sub_type_count; i++)
		free_typecheck_type(&typecheck_type->sub_types[i]);
	if (typecheck_type->type >= TYPE_SUPER_ARRAY && typecheck_type->sub_type_count)
		free(typecheck_type->sub_types);
}

const int copy_typecheck_type(typecheck_type_t* dest, typecheck_type_t src) {
	dest->type = src.type;
	dest->sub_type_count = src.sub_type_count;
	dest->match = src.match;
	if (src.type >= TYPE_SUPER_ARRAY && src.sub_type_count) {
		ESCAPE_ON_FAIL(dest->sub_types = malloc(src.sub_type_count * sizeof(typecheck_type_t)));
		for (uint_fast8_t i = 0; i < src.sub_type_count; i++)
			copy_typecheck_type(&dest->sub_types[i], src.sub_types[i]);
	}
	else
		dest->sub_types = NULL;
	return 1;
}

const int typecheck_type_compatible(typecheck_type_t* target_type, typecheck_type_t match_type) {
	if (target_type->type == TYPE_AUTO)
		return copy_typecheck_type(target_type, match_type);
	else if (target_type->type < TYPE_SUPER_ARRAY)
		return target_type->type == match_type.type;
	else {
		if (target_type->type != match_type.type)
			return 0;
		if (target_type->type >= TYPE_SUPER_ARRAY) {
			if (target_type->sub_type_count != match_type.sub_type_count)
				return 0;
			for (uint_fast8_t i = 0; i < target_type->sub_type_count; i++)
				ESCAPE_ON_FAIL(typecheck_type_compatible(&target_type->sub_types[i], match_type.sub_types[i]));
		}
		else if (target_type->type == TYPE_TYPEARG)
			return target_type->match == match_type.match;
		return 1;
	}
}

const int init_type_matcher(type_matcher_t* type_matcher, typecheck_type_t param_type) {
	ESCAPE_ON_FAIL(copy_typecheck_type(&type_matcher->out_type, param_type));
	ESCAPE_ON_FAIL(type_matcher->match_flags = calloc(TYPE_MAX_SUBTYPES, sizeof(int)));
	ESCAPE_ON_FAIL(type_matcher->match_types = malloc(TYPE_MAX_SUBTYPES * sizeof(typecheck_type_t)));
	return 1;
}

void free_type_matcher(type_matcher_t* type_matcher) {
	free_typecheck_type(&type_matcher->out_type);
	free(type_matcher->match_flags);
	free(type_matcher->match_types);
}

const int type_matcher_add(type_matcher_t* matcher, typecheck_type_t* param, typecheck_type_t arg) {
	if (param->type == TYPE_TYPEARG) {
		uint8_t match = param->match;
		if (matcher->match_flags[match])
			return typecheck_type_compatible(&matcher->match_types[match], arg);
		if (arg.type == TYPE_NOTHING)
			return 0;
		matcher->match_flags[match] = 1;
		free_typecheck_type(param);
		ESCAPE_ON_FAIL(copy_typecheck_type(param, arg));
		matcher->match_types[match] = *param;
		return 1;
	}
	ESCAPE_ON_FAIL(param->type == arg.type);
	if (param->type >= TYPE_SUPER_ARRAY) {
		ESCAPE_ON_FAIL(param->sub_type_count == arg.sub_type_count);
		for (uint_fast8_t i = 0; i < param->sub_type_count; i++)
			ESCAPE_ON_FAIL(type_matcher_add(matcher, &param->sub_types[0], arg.sub_types[0]));
	}
	return 1;
}

static const int finalize_param(type_matcher_t* type_matcher, typecheck_type_t* param) {
	if (param->type == TYPE_TYPEARG) {
		ESCAPE_ON_FAIL(type_matcher->match_flags[param->match]);
		ESCAPE_ON_FAIL(copy_typecheck_type(param, type_matcher->match_types[param->match]));
	}
	else if (param->type >= TYPE_SUPER_ARRAY) {
		for (uint_fast8_t i = 0; i < param->sub_type_count; i++)
			ESCAPE_ON_FAIL(finalize_param(type_matcher, &param->sub_types[i]));
	}
	return 1;
}

const int type_matcher_finalize(type_matcher_t* type_matcher) {
	ESCAPE_ON_FAIL(finalize_param(type_matcher, &type_matcher->out_type));
	return 1;
}