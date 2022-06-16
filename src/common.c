#include "common.h"

const char* get_filepath_ext(const char* path) {
	while (*path && *path != '.') {
		++path;
	}
	return ++path;
}