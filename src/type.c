#include <stdlib.h>
#include "error.h"
#include "ast.h"
#include "type.h"

void free_typecheck_type(typecheck_type_t* typecheck_type) {
	if (typecheck_type->type >= TYPE_SUPER_ARRAY && typecheck_type->sub_type_count) {
		for (uint_fast8_t i = 0; i < typecheck_type->sub_type_count; i++)
			free_typecheck_type(&typecheck_type->sub_types[i]);
		free(typecheck_type->sub_types);
	}
}

int copy_typecheck_type(typecheck_type_t* dest, typecheck_type_t src) {
	dest->type = src.type;
	dest->type_id = src.type_id;
	if (src.type >= TYPE_SUPER_ARRAY && src.sub_type_count) {
		dest->sub_type_count = src.sub_type_count;
		ESCAPE_ON_FAIL(dest->sub_types = malloc(src.sub_type_count * sizeof(typecheck_type_t)));
		for (uint_fast8_t i = 0; i < src.sub_type_count; i++)
			copy_typecheck_type(&dest->sub_types[i], src.sub_types[i]);
	}
	else {
		dest->sub_types = NULL;
		dest->sub_type_count = 0;
	}
	return 1;
}

int typecheck_compatible(ast_t* ast, typecheck_type_t* target_type, typecheck_type_t match_type) {
	if (match_type.type == TYPE_ANY)
		return 1;
	else if (target_type->type == TYPE_AUTO)
		return copy_typecheck_type(target_type, match_type);
	else {
		ESCAPE_ON_FAIL(target_type->type == match_type.type);
		if (target_type->type == TYPE_TYPEARG)
			return target_type->type_id == match_type.type_id;
		if (target_type->type == TYPE_SUPER_RECORD && target_type->type_id != match_type.type_id) {
			ast_record_proto_t* record_proto = ast->record_protos[target_type->type_id];

			typecheck_type_t current_rec_type;
			ESCAPE_ON_FAIL(copy_typecheck_type(&current_rec_type, *target_type));
			
			int res = 0;
			do {
				//ESCAPE_ON_FAIL(record_proto->typeargs_defined);
				if (!record_proto->base_record)
					goto typecheck_record_failed;
				typecheck_type_t next_rec_type;
				ESCAPE_ON_FAIL(copy_typecheck_type(&next_rec_type, *record_proto->base_record));
				ESCAPE_ON_FAIL(typeargs_substitute(current_rec_type.sub_types, &next_rec_type));
				free_typecheck_type(&current_rec_type);
				current_rec_type = next_rec_type;
				record_proto = ast->record_protos[current_rec_type.type_id];
			} while (current_rec_type.type_id != match_type.type_id);
			res = typecheck_compatible(ast, &current_rec_type, match_type);
		typecheck_record_failed:
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

int typecheck_lowest_common_type(ast_t* ast, typecheck_type_t a, typecheck_type_t b, typecheck_type_t* result) {
	if (a.type != b.type) {
		*result = typecheck_any;
		return 1;
	}
	typecheck_type_t common_type = { .type = a.type };
	if (a.type == TYPE_SUPER_RECORD) {
		if (a.type_id != b.type_id) {
			typecheck_type_t a_rec_type;
			ESCAPE_ON_FAIL(copy_typecheck_type(&a_rec_type, a));
			
			for (;;) {
				ast_record_proto_t* record_a = ast->record_protos[a_rec_type.type_id];

				typecheck_type_t b_rec_type;
				ESCAPE_ON_FAIL(copy_typecheck_type(&b_rec_type, b));
				for (;;) {
					ast_record_proto_t* record_b = ast->record_protos[b_rec_type.type_id];
					
					if (record_a == record_b) {
						common_type.type_id = record_a->id;
						common_type.sub_type_count = record_a->generic_arguments;
						ESCAPE_ON_FAIL(common_type.sub_types = malloc(common_type.sub_type_count * sizeof(typecheck_type_t)));
						for (uint_fast8_t i = 0; i < a_rec_type.sub_type_count; i++)
							ESCAPE_ON_FAIL(typecheck_lowest_common_type(ast, a.sub_types[i], b.sub_types[i], &common_type.sub_types[i]));
						free_typecheck_type(&a_rec_type);
						free_typecheck_type(&b_rec_type);
						*result = common_type;
						return 1;
					}

					if (!record_b->base_record) {
						free_typecheck_type(&b_rec_type);
						break;
					}
					else {
						typecheck_type_t next_b_rec_type;
						ESCAPE_ON_FAIL(copy_typecheck_type(&next_b_rec_type, *record_b->base_record));
						ESCAPE_ON_FAIL(typeargs_substitute(b_rec_type.sub_types, &next_b_rec_type));
						free_typecheck_type(&b_rec_type);
						b_rec_type = next_b_rec_type;
					}
				}
				
				if (!record_a->base_record) {
					free_typecheck_type(&a_rec_type);
					break;
				}
				else {
					typecheck_type_t next_a_rec_type;
					ESCAPE_ON_FAIL(copy_typecheck_type(&next_a_rec_type, *record_a->base_record));
					ESCAPE_ON_FAIL(typeargs_substitute(a_rec_type.sub_types, &next_a_rec_type));
					free_typecheck_type(&a_rec_type);
					a_rec_type = next_a_rec_type;
				}
			}
			*result = typecheck_any;
			return 1;
		}
		common_type.type_id = a.type_id;
	}
	if (a.type == TYPE_SUPER_PROC) {
		if (a.type_id != b.type_id) {
			*result = typecheck_any;
			return 1;
		}
	}
	if (a.type >= TYPE_SUPER_ARRAY) {
		if (a.sub_type_count != b.sub_type_count) {
			*result = typecheck_any;
			return 1;
		}
		common_type.sub_type_count = a.sub_type_count;
		ESCAPE_ON_FAIL(common_type.sub_types = malloc(common_type.sub_type_count * sizeof(typecheck_type_t)));
		for (uint_fast8_t i = 0; i < common_type.sub_type_count; i++)
			ESCAPE_ON_FAIL(typecheck_lowest_common_type(ast, a.sub_types[i], b.sub_types[i], &common_type.sub_types[i]));
	}
	*result = common_type;
	return 1;
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

int typeargs_substitute(typecheck_type_t* input_typeargs, typecheck_type_t* proto_type) {
	if (proto_type->type == TYPE_TYPEARG)
		ESCAPE_ON_FAIL(copy_typecheck_type(proto_type, input_typeargs[proto_type->type_id]))
	else if (proto_type->type >= TYPE_SUPER_ARRAY) {
		for (uint_fast8_t i = 0; i < proto_type->sub_type_count; i++)
			ESCAPE_ON_FAIL(typeargs_substitute(input_typeargs, &proto_type->sub_types[i]));
	}
	return 1;
}