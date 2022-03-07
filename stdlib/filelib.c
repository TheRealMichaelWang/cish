#include <stdlib.h>
#include <stdio.h>
#include "superforth.h"

#ifdef _WIN32
#include <io.h>
#include <sys/stat.h>
#else
#include <dirent.h>
#endif


#define ESCAPE_ON_FAIL(WHAT) if(!(WHAT)) { return 0; }
 
enum filesystem_type {
	FILESYSTEM_NONE = 0,
	FILESYSTEM_FILE,
	FILESYSTEM_DIR
} selected_type = FILESYSTEM_NONE;

static char path_buffer[256];
static int exists = 0;

static int set_path_buffer(heap_alloc_t* path_str) {
	if (path_str->limit > 256)
		return 0;
	for (int i = 0; i < path_str->limit; i++)
		path_buffer[i] = path_str->registers[i].char_int;
	return 1;
}

int ffi_select_file(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(!selected_type);
	ESCAPE_ON_FAIL(set_path_buffer(in->heap_alloc));
	FILE* file = fopen(path_buffer, "r");
	if (file) {
		exists = 1;
		fclose(file);
	}
	else
		exists = 0;
	selected_type = FILESYSTEM_FILE;
	return 1;
}

int ffi_select_dir(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(!selected_type);
	ESCAPE_ON_FAIL(set_path_buffer(in->heap_alloc));

#ifdef _WIN32
	if (_access(path_buffer, 0) == 0) {
		struct stat status;
		stat(path_buffer, &status);
		exists = (status.st_mode & S_IFDIR) != 0;
	}
	else
		exists = 0;
#else
	DIR* dir = opendir(path_buffer);
	if (dir) {
		closedir(dir);
		exists = 1;
	}
	else
		exists = 0;
#endif
	selected_type = FILESYSTEM_DIR;
	return 1;
}

int ffi_file_exists(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(selected_type);
	out->bool_flag = exists;
	return 1;
}

int ffi_create_file(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(selected_type);
	ESCAPE_ON_FAIL(!exists);
	FILE* created_file = fopen(path_buffer, "w");
	ESCAPE_ON_FAIL(created_file);
	fclose(created_file);
	exists = 1;
	return 1;
}

int ffi_read_file(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(selected_type);
	ESCAPE_ON_FAIL(exists);

	FILE* in_file = fopen(path_buffer, "rb");
	ESCAPE_ON_FAIL(in_file);
	
	fseek(in_file, 0, SEEK_END);
	long size = ftell(in_file);
	fseek(in_file, 0, SEEK_SET);

	char* buffer = malloc(size * sizeof(char));
	if (!buffer) {
		fclose(in_file);
		return 0;
	}
	fread(buffer, sizeof(char), size, in_file);
	fclose(in_file);

	if (!(out->heap_alloc = machine_alloc(machine, size, GC_TRACE_MODE_ALL))) {
		free(buffer);
		return 0;
	}

	if (in->bool_flag) { //read chars
		for (uint_fast16_t i = 0; i < out->heap_alloc->limit; i++)
			out->heap_alloc->registers[i].char_int = buffer[i];
	}
	else { //read bytes
		for (uint_fast16_t i = 0; i < out->heap_alloc->limit; i++)
			out->heap_alloc->registers[i].long_int = buffer[i];
	}
	free(buffer);
	selected_type = FILESYSTEM_NONE;
	return 1;
}

int ffi_write_file_text(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(selected_type);
	ESCAPE_ON_FAIL(exists);
	
	FILE* in_file = fopen(path_buffer, "wb");
	ESCAPE_ON_FAIL(in_file);

	char* buffer = malloc(in->heap_alloc->limit);
	if (!buffer) {
		fclose(in_file);
		return 0;
	}

	for (uint_fast16_t i = 0; i < in->heap_alloc->limit; i++)
		buffer[i] = in->heap_alloc->registers[i].char_int;
	
	fwrite(buffer, sizeof(char), in->heap_alloc->limit, in_file);
	free(buffer);
	fclose(in_file);
	return 1;
}

int ffi_write_file_bytes(machine_t* machine, machine_reg_t* in, machine_reg_t* out) {
	ESCAPE_ON_FAIL(selected_type);
	ESCAPE_ON_FAIL(exists);

	FILE* in_file = fopen(path_buffer, "wb");
	ESCAPE_ON_FAIL(in_file);

	char* buffer = malloc(in->heap_alloc->limit);
	if (!buffer) {
		fclose(in_file);
		return 0;
	}

	for (uint_fast16_t i = 0; i < in->heap_alloc->limit; i++)
		if (in->heap_alloc->registers[i].long_int >= 256) {
			free(buffer);
			fclose(in_file);
			return 0;
		}

	fwrite(buffer, sizeof(char), in->heap_alloc->limit, in_file);
	free(buffer);
	fclose(in_file);
	return 1;
}

SUPERFORTH_ENTRY({
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_select_file));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_select_dir));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_file_exists));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_create_file));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_read_file));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_write_file_bytes));
	ESCAPE_ON_FAIL(ffi_include_func(&machine->ffi_table, ffi_write_file_text));
	return 1;
});