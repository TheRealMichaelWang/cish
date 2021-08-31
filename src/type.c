#include <stdlib.h>
#include "error.h"
#include "type.h"

void free_typecheck_type(typecheck_type_t* typecheck_type) {
	for (uint_fast8_t i = 0; i < typecheck_type->sub_type_count; i++)
		free_typecheck_type(&typecheck_type->sub_types[i]);
	if (typecheck_type->sub_types)
		free(typecheck_type->sub_types);
}

const int copy_typecheck_type(typecheck_type_t* dest, typecheck_type_t src) {
	dest->type = src.type;
	dest->sub_type_count = src.sub_type_count;
	dest->match = src.match;
	if (src.sub_type_count) {
		ESCAPE_ON_NULL(dest->sub_types = malloc(src.sub_type_count * sizeof(typecheck_type_t)));
		for (uint_fast8_t i = 0; i < src.sub_type_count; i++)
			copy_typecheck_type(&dest->sub_types[i], src.sub_types[i]);
	}
	else
		dest->sub_types = NULL;
	return 1;
}

const int typecheck_type_compatible(typecheck_type_t target_type, typecheck_type_t match_type) {
	if (target_type.type == TYPE_TYPEARG && match_type.type == TYPE_TYPEARG)
		return target_type.match == match_type.match;
	if (target_type.type < TYPE_SUPER_ARRAY)
		return target_type.type == match_type.type;
	else {
		if (target_type.type != match_type.type || target_type.sub_type_count != match_type.sub_type_count)
			return 0;
		for (uint_fast8_t i = 0; i < target_type.sub_type_count; i++)
			if (target_type.sub_types[i].type != match_type.sub_types[i].type)
				return 0;
		return 1;
	}
}

const int init_type_matcher(type_matcher_t* type_matcher, typecheck_type_t param_type, typecheck_type_t* arg_type) {
	type_matcher->param_type = param_type;
	ESCAPE_ON_NULL(copy_typecheck_type(arg_type, param_type));
	ESCAPE_ON_NULL(type_matcher->match_flags = calloc(TYPE_MAX_SUBTYPES, sizeof(int)));
	ESCAPE_ON_NULL(type_matcher->match_types = malloc(TYPE_MAX_SUBTYPES * sizeof(typecheck_type_t)));
	return 1;
}

void free_type_matcher(type_matcher_t* type_matcher) {
	free(type_matcher->match_flags);
	free(type_matcher->match_types);
}

