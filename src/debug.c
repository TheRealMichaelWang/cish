#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "debug.h"

static const char* error_names[] = {
	"none",
	"memory",
	"internal",

	"unexpected token",

	"cannot set readonly var",
	"unallowed type",

	"undeclared",
	"redeclaration",

	"unexpected type",
	"unexpected argument length",

	"cannot return",
	"cannot break",
	"cannot continue",
	"cannot extend(is final)",
	"cannot initialize(is abstract)",

	"index out of range",
	"divide by zero",
	"stack overflow",
	"read unitialized memory",

	"function unable to return",
	
	"program aborted",
	"foreign error",
	"cannot open file"
};

const char* get_err_msg(error_t error) {
	return error_names[error];
}

void print_error_trace(multi_scanner_t multi_scanner) {
	if (multi_scanner.current_file) {
		for (uint_fast8_t i = 0; i < multi_scanner.current_file; i++)
			printf("in %s: row %" PRIu32 ", col %"PRIu32 "\n", multi_scanner.file_paths[i], multi_scanner.scanners[i].row, multi_scanner.scanners[i].col);
		printf("\t");
	}
	if (multi_scanner.last_tok.type == TOK_EOF) {
		printf("Error Occured at EOF");
	}
	else {
		for (uint_fast32_t i = 0; i < multi_scanner.last_tok.length; i++)
			printf("%c", multi_scanner.last_tok.str[i]);
		for (uint_fast8_t i = multi_scanner.last_tok.length; multi_scanner.last_tok.str[i] && multi_scanner.last_tok.str[i] != '\n'; i++)
			printf("%c", multi_scanner.last_tok.str[i]);
	}
	printf("\n");
}