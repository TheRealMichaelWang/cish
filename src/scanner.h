#pragma once

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include "error.h"
#include "tokens.h"

typedef struct scanner {
	const char* source;
	uint32_t length, position, row, col;

	token_t last_tok;
	char last_char;

	error_t last_err;
} scanner_t;

typedef struct multi_scanner {
	char* file_paths[32];
	char* sources[32];
	uint64_t visited_hashes[64];
	uint8_t visited_files;

	scanner_t scanners[32];
	uint8_t current_scanner;

	token_t last_tok;
	error_t last_err;
} multi_scanner_t;

void init_scanner(scanner_t* scanner, const char* source, const uint32_t length, int init_scan);

const int scanner_scan_char(scanner_t* scanner);
const int scanner_scan_tok(scanner_t* scanner);

void init_multi_scanner(multi_scanner_t* scanner, const char* source, const uint32_t length);
void free_multi_scanner(multi_scanner_t* scanner);
const int multi_scanner_visit(multi_scanner_t* scanner, const char* file);
const int multi_scanner_scan_tok(multi_scanner_t* scanner);

#endif // !SCANNER_H