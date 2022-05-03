#pragma once

#ifndef ERROR_H

#include <stdint.h>
#include <stddef.h>

typedef enum error {
	ERROR_NONE,
	ERROR_MEMORY,
	ERROR_INTERNAL,

	//syntax errors
	ERROR_UNEXPECTED_TOK,

	ERROR_READONLY,
	ERROR_TYPE_NOT_ALLOWED,

	ERROR_UNDECLARED,
	ERROR_REDECLARATION,

	ERROR_UNEXPECTED_TYPE,
	ERROR_UNEXPECTED_ARGUMENT_SIZE,

	ERROR_CANNOT_RETURN,
	ERROR_CANNOT_CONTINUE,
	ERROR_CANNOT_BREAK,
	ERROR_CANNOT_EXTEND,
	ERROR_CANNOT_INIT,

	//virtual-machine errors
	ERROR_INDEX_OUT_OF_RANGE,
	ERROR_DIVIDE_BY_ZERO,
	ERROR_STACK_OVERFLOW,
	ERROR_READ_UNINIT,

	ERROR_UNRETURNED_FUNCTION,
	
	ERROR_ABORT,
	ERROR_FOREIGN,

	ERROR_CANNOT_OPEN_FILE
} error_t;

typedef struct safe_gc {
	void** entries;
	void*** availible_entries;

	void** transfer_entries;

	uint64_t entry_count, alloced_entries, avaible_entry_count, alloced_availible_entries, transfer_entry_count, alloced_transfer_entries;
} safe_gc_t;

#define PANIC(OBJ, ERROR){ OBJ->last_err = ERROR; return 0; }
#define ESCAPE_ON_FAIL(PTR) {if(!(PTR)) { return 0; }}
#define PANIC_ON_FAIL(PTR, OBJ, ERROR) {if(!(PTR)) PANIC(OBJ, ERROR)}

int init_safe_gc(safe_gc_t* safe_gc);
void free_safe_gc(safe_gc_t* safe_gc, int free_transfers);

void* safe_malloc(safe_gc_t* safe_gc, int size);
void* safe_calloc(safe_gc_t* safe_gc, int count, size_t size);
void* safe_realloc(safe_gc_t* safe_gc, void* ptr, int new_size);
int safe_free(safe_gc_t* safe_gc, void* data);

void* safe_transfer_malloc(safe_gc_t* safe_gc, int size);
void* safe_add_managed(safe_gc_t* safe_gc, void* alloc);

#endif // !ERROR_H
