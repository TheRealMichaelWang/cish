#include <stdlib.h>
#include "error.h"
#include "ast.h"
#include "type.h"

void free_typecheck_type(typecheck_type_t* typecheck_type) {
	if (typecheck_type->type >= TYPE_SUPER_ARRAY) {
		for (uint_fast8_t i = 0; i < typecheck_type->sub_type_count; i++)
			free_typecheck_type(&typecheck_type->sub_types[i]);
		free(typecheck_type->sub_types);
	}
}

int copy_typecheck_type(typecheck_type_t* dest, typecheck_type_t src) {
	dest->type = src.type;
	dest->sub_type_count = src.sub_type_count;
	dest->type_id = src.type_id;
	if (src.type >= TYPE_SUPER_ARRAY && src.sub_type_count) {
		ESCAPE_ON_FAIL(dest->sub_types = malloc(src.sub_type_count * sizeof(typecheck_type_t)));
		for (uint_fast8_t i = 0; i < src.sub_type_count; i++)
			copy_typecheck_type(&dest->sub_types[i], src.sub_types[i]);
	}
	else
		dest->sub_types = NULL;
	return 1;
}

int typecheck_compatible(ast_t* ast, typecheck_type_t* target_type, typecheck_type_t match_type) {
	if (target_type->type == TYPE_AUTO)
		return copy_typecheck_type(target_type, match_type);
	else {
		ESCAPE_ON_FAIL(target_type->type == match_type.type);
		if (target_type->type == TYPE_TYPEARG)
			return target_type->type_id == match_type.type_id;
		if (target_type->type == TYPE_SUPER_RECORD && target_type->type_id != match_type.type_id) {
			ast_record_proto_t* record_proto = ast->record_protos[target_type->type_id];

			typecheck_type_t current_rec_type;
			ESCAPE_ON_FAIL(copy_typecheck_type(&current_rec_type, *target_type));

			do {
				ESCAPE_ON_FAIL(record_proto->defined);

				typecheck_type_t next_rec_type;
				ESCAPE_ON_FAIL(copy_typecheck_type(&next_rec_type, *record_proto->base_record));
				ESCAPE_ON_FAIL(type_args_substitute(current_rec_type, &next_rec_type));
				free_typecheck_type(&current_rec_type);
				current_rec_type = next_rec_type;
				record_proto = ast->record_protos[current_rec_type.type_id];
			} while (current_rec_type.type_id != match_type.type_id);
			int res = typecheck_compatible(ast, &current_rec_type, match_type);
			free_typecheck_type(&current_rec_type);
			return res;
		}
		if (target_type->type >= TYPE_SUPER_ARRAY) {
			ESCAPE_ON_FAIL(target_type->sub_type_count == match_type.sub_type_count);
			for (uint_fast8_t i = 0; i < target_type->sub_type_count; i++)
				ESCAPE_ON_FAIL(typecheck_compatible(ast, &target_type->sub_types[i], match_type.sub_types[i]));
		}
		return 1;
	}
}

int typecheck_has_type(typecheck_type_t type, typecheck_base_type_t base_type) {
	if (type.type == base_type)
		return 1;
	if (type.type >= TYPE_SUPER_ARRAY)
		for (uint_fast8_t i = 0; i < type.sub_type_count; i++)
			if (typecheck_has_type(type.sub_types[i], base_type))
				return 1;
	return 0;
}

int type_args_substitute(typecheck_type_t input_type_args, typecheck_type_t* proto_type) {
	if (proto_type->type == TYPE_TYPEARG)
		ESCAPE_ON_FAIL(copy_typecheck_type(proto_type, input_type_args.sub_types[proto_type->type_id]))
	else if (proto_type->type >= TYPE_SUPER_ARRAY) {
		for (uint_fast8_t i = 0; i < proto_type->sub_type_count; i++)
			ESCAPE_ON_FAIL(type_args_substitute(input_type_args, &proto_type->sub_types[i]));
	}
	return 1;
}