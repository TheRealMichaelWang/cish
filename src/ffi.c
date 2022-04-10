#include <stdlib.h>
#include "ffi.h"
#include "machine.h"
#include "error.h"

#ifdef _WIN32
#define WIN_32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int init_ffi(ffi_t* ffi_table) {
	ESCAPE_ON_FAIL(ffi_table->func_table = malloc((ffi_table->func_alloc = 64) * sizeof(foreign_func)));
	ffi_table->func_count = 0;
	return 1;
}

void free_ffi(ffi_t* ffi_table) {
	free(ffi_table->func_table);
}

int ffi_include_func(ffi_t* ffi_table, foreign_func func) {
	if (ffi_table->func_count == ffi_table->func_alloc) {
		foreign_func* new_table = realloc(ffi_table->func_table, (ffi_table->func_alloc *= 2) * sizeof(foreign_func));
		ESCAPE_ON_FAIL(new_table);
		ffi_table->func_table = new_table;
	}
	ffi_table->func_table[ffi_table->func_count++] = func;
	return 1;
}

int ffi_invoke(ffi_t* ffi_table, machine_t* machine, machine_reg_t* id_reg, machine_reg_t* in_reg, machine_reg_t* out_reg) {
	if (id_reg->long_int >= ffi_table->func_count || id_reg->long_int < 0)
		return 0;
	return ffi_table->func_table[id_reg->long_int](machine, in_reg, out_reg);
}

int dynamic_library_init(dynamic_library_table_t* dynamic_library) {
	dynamic_library->imported_lib_count = 0;
	ESCAPE_ON_FAIL(dynamic_library->imported_libs = malloc(256 * sizeof(dynamic_library_t)));
	return 1;
}

void dynamic_library_free(dynamic_library_table_t* dynamic_library) {
	for (uint_fast16_t i = 0; i < dynamic_library->imported_lib_count; i++) {
		free(dynamic_library->imported_libs[i].name);
#ifdef _WIN32
		FreeLibrary(dynamic_library->imported_libs[i].handle);
#else
		dlclose(dynamic_library->imported_libs[i].handle);
#endif
	}
	free(dynamic_library->imported_libs);
}

int dynamic_library_load(dynamic_library_table_t* dynamic_library, machine_t* machine, char* name) {
	if (dynamic_library->imported_lib_count == UINT8_MAX)
		return 0;
	dynamic_library_t* new_lib = &dynamic_library->imported_libs[dynamic_library->imported_lib_count];
	new_lib->name = name;
#ifdef _WIN32
	static wchar_t libid_buf[100];
	mbstowcs(libid_buf, name, 100);
	ESCAPE_ON_FAIL(new_lib->handle = LoadLibrary(libid_buf));
	if (!(new_lib->entry_point = GetProcAddress(new_lib->handle, TEXT("superforth_entry")))) {
		free(name);
		FreeLibrary(new_lib->handle);
		return 0;
	}
#else
	ESCAPE_ON_FAIL(new_lib->handle = dlopen(name, RTLD_LAZY));
	if (!(new_lib->entry_point = dlsym(new_lib->handle, "superforth_entry"))) {
		free(name);
		dlclose(new_lib->handle);
		return 0;
	}
#endif
	ESCAPE_ON_FAIL(new_lib->entry_point(machine));
	dynamic_library->imported_lib_count++;
	return 1;
}