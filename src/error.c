#include <stdlib.h>
#include "error.h"

int init_safe_gc(safe_gc_t* safe_gc) {
	ESCAPE_ON_FAIL(safe_gc->entries = malloc((safe_gc->alloced_entries = 25) * sizeof(void*)));
	ESCAPE_ON_FAIL(safe_gc->availible_entries = malloc((safe_gc->alloced_availible_entries = 5) * sizeof(void**)));
	ESCAPE_ON_FAIL(safe_gc->transfer_entries = malloc((safe_gc->alloced_transfer_entries = 5) * sizeof(void*)));
	safe_gc->entry_count = 0;
	safe_gc->avaible_entry_count = 0;
	safe_gc->transfer_entry_count = 0;
	return 1;
}

void free_safe_gc(safe_gc_t* safe_gc, int free_transfers) {
	for (uint_fast64_t i = 0; i < safe_gc->entry_count; i++) {
		if (safe_gc->entries[i])
			free(safe_gc->entries[i]);
	}
	if (free_transfers) {
		for (uint_fast64_t i = 0; i < safe_gc->transfer_entry_count; i++)
			if(safe_gc->transfer_entries[i])
				free(safe_gc->transfer_entries[i]);
	}
	free(safe_gc->entries);
	free(safe_gc->availible_entries);
	free(safe_gc->transfer_entries);
}

static void** new_entry(safe_gc_t* safe_gc) {
	if (safe_gc->avaible_entry_count)
		return safe_gc->availible_entries[--safe_gc->avaible_entry_count];
	else {
		if (safe_gc->entry_count == safe_gc->alloced_entries) {
			void** new_entries = realloc(safe_gc->entries, (safe_gc->alloced_entries += 10) * sizeof(void*));
			ESCAPE_ON_FAIL(new_entries);
			safe_gc->entries = new_entries;
		}
		return &safe_gc->entries[safe_gc->entry_count++];
	}
}

static void** find_entry(safe_gc_t* safe_gc, void* data, int no_transfer) {
	ESCAPE_ON_FAIL(data);
	for (uint_fast64_t i = 0; i < safe_gc->entry_count; i++)
		if (safe_gc->entries[i] == data)
			return &safe_gc->entries[i];
	if (no_transfer)
		return NULL;
	for (uint_fast64_t i = 0; i < safe_gc->transfer_entry_count; i++)
		if (safe_gc->transfer_entries[i] == data)
			return &safe_gc->transfer_entries[i];
	return NULL;
}

void* safe_malloc(safe_gc_t* safe_gc, int size) {
	void* data = malloc(size);

	ESCAPE_ON_FAIL(data);

	void** entry = new_entry(safe_gc);
	if (!entry) {
		free(data);
		return 0;
	}
	else {
		*entry = data;
		return data;
	}
}

void* safe_transfer_malloc(safe_gc_t* safe_gc, int size) {
	void* data = malloc(size);
	ESCAPE_ON_FAIL(data);

	if (safe_gc->transfer_entry_count == safe_gc->alloced_transfer_entries) {
		void* new_transfer_entries = realloc(safe_gc->transfer_entries, (safe_gc->alloced_transfer_entries += 2) * sizeof(void*));
		if (!new_transfer_entries) {
			free(data);
			return NULL;
		}
		safe_gc->transfer_entries = new_transfer_entries;
	}
	return safe_gc->transfer_entries[safe_gc->transfer_entry_count++] = data;
}

void* safe_calloc(safe_gc_t* safe_gc, int count, size_t size) {
	void* data = calloc(count, size);

	ESCAPE_ON_FAIL(data);

	void** entry = new_entry(safe_gc);
	if (!entry) {
		free(data);
		return 0;
	}
	else {
		*entry = data;
		return data;
	}
}

void* safe_add_managed(safe_gc_t* safe_gc, void* alloc) {
	ESCAPE_ON_FAIL(alloc);

	void** entry = new_entry(safe_gc);
	ESCAPE_ON_FAIL(entry);

	*entry = alloc;
	return alloc;
}

void* safe_realloc(safe_gc_t* safe_gc, void* data, int new_size) {
	void** entry = find_entry(safe_gc, data, 0);
	ESCAPE_ON_FAIL(entry);
	ESCAPE_ON_FAIL(data = realloc(data, new_size));
	*entry = data;
	return data;
}

int safe_free(safe_gc_t* safe_gc, void* data) {
	void** entry = find_entry(safe_gc, data, 1);
	ESCAPE_ON_FAIL(entry);
	free(data);
	*entry = NULL;
	
	if (safe_gc->avaible_entry_count == safe_gc->alloced_availible_entries) {
		void*** new_availible_entries = realloc(safe_gc->availible_entries, (safe_gc->alloced_availible_entries += 5) * sizeof(void**));
		ESCAPE_ON_FAIL(new_availible_entries);
		safe_gc->availible_entries = new_availible_entries;
	}
	safe_gc->availible_entries[safe_gc->avaible_entry_count++] = entry;
	return 1;
}