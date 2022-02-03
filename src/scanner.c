#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"
#include "file.h"
#include "scanner.h"

static char scanner_peek_char(scanner_t* scanner) {
	if (scanner->length == scanner->position)
		return 0;
	return scanner->source[scanner->position];
}

static char scanner_read_char(scanner_t* scanner) {
	if (scanner->length == scanner->position)
		return scanner->last_char = 0;
	scanner->col++;
	if (scanner->source[scanner->position] == '\n') {
		scanner->col = 0;
		scanner->row++;
	}
	return scanner->last_char = scanner->source[scanner->position++];
}

void init_scanner(scanner_t* scanner, const char* source, uint32_t length) {
	scanner->source = source;
	scanner->length = length;
	scanner->position = 0;
	scanner->row = 1;
	scanner->col = 0;
	scanner->last_err = ERROR_NONE;
}

#define RETURN(TYPE) { scanner->last_char = TYPE; break; }
int scanner_scan_char(scanner_t* scanner) {
	scanner_read_char(scanner);
	if (scanner->last_char == '\\') {
		scanner_read_char(scanner);
		switch (scanner->last_char)
		{
		case 'b':
			RETURN('\b');
		case 'e':
			RETURN('\e');
		case 'n':
			RETURN('\n');
		case 'r':
			RETURN('\r');
		case 't':
			RETURN('\t');
		case '\\':
			RETURN('\\');
		case '\"':
			RETURN('\"');
		case '0':
			RETURN(0);
		default:
			PANIC(scanner, ERROR_UNEXPECTED_TOK);
		}
	}
	return 1;
}
#undef RETURN

#define RETURN(TYPE) {scanner->last_tok.type = TYPE; break;}
int scanner_scan_tok(scanner_t* scanner) {
	while (scanner->last_char == ' ' || scanner->last_char == '\t' || scanner->last_char == '\r' || scanner->last_char == '\n')
		scanner_read_char(scanner);

	scanner->last_tok.str = &scanner->source[scanner->position - 1];
	scanner->last_tok.length = 0;

	if (isalpha(scanner->last_char) || scanner->last_char == '_') {
		do {
			scanner_read_char(scanner);
			scanner->last_tok.length++;
		} while (isalpha(scanner->last_char) || isalnum(scanner->last_char) || scanner->last_char == '_');
		uint64_t id_hash = hash_s(scanner->last_tok.str, scanner->last_tok.length);
		switch (id_hash)
		{
		case 229465117490944:
			RETURN(TOK_EXTEND);
		case 7572877634356771:
			RETURN(TOK_READONLY);
		case 229466054363183:
			RETURN(TOK_FOREIGN);
		case 7572251799911306: //continue
			RETURN(TOK_CONTINUE);
		case 210707980106: //break
			RETURN(TOK_BREAK);
		case 210706230653: //abort
			RETURN(TOK_ABORT);
		case 6385087377: //bool
			RETURN(TOK_TYPECHECK_BOOL);
		case 6385115235: //char
			RETURN(TOK_TYPECHECK_CHAR);
		case 193495088: //long
			RETURN(TOK_TYPECHECK_LONG);
		case 210712519067: //float
			RETURN(TOK_TYPECHECK_FLOAT);
		case 210706808356: //array
			RETURN(TOK_TYPECHECK_ARRAY);
		case 6385593753: //proc
			RETURN(TOK_TYPECHECK_PROC);
		case 229476388586812: //nothing
			RETURN(TOK_NOTHING);
		case 6385058142: //auto
			RETURN(TOK_AUTO);
		case 6953552265174: //global
			RETURN(TOK_GLOBAL);
		case 5863476: //if
			RETURN(TOK_IF);
		case 6385192046: //else
			RETURN(TOK_ELSE);
		case 210732529790: //while
			RETURN(TOK_WHILE);
		case 6953974653989:
			RETURN(TOK_RETURN);
		case 6385737701: //true
			RETURN(TOK_TRUE);
		case 210712121072: //false
			RETURN(TOK_FALSE);
		case 193486360: //and
			RETURN(TOK_AND);
		case 5863686: //or
			RETURN(TOK_OR);
		case 193500239:
			RETURN(TOK_NEW);
		case 229469872107401:
			RETURN(TOK_INCLUDE);
		case 6953974036516:
			RETURN(TOK_RECORD);
		case 193504585: //rem
			do {
				scanner_read_char(scanner);
			} while (scanner->last_char != '\n');
			return scanner_scan_tok(scanner);
		default:
			RETURN(TOK_IDENTIFIER);
		}
	}
	else if (isalnum(scanner->last_char)) {
		do {
			scanner_read_char(scanner);
			scanner->last_tok.length++;
		} while (isalnum(scanner->last_char) || scanner->last_char == '.');
		scanner->last_tok.type = TOK_NUMERICAL;
	}
	else if (scanner->last_char == '\"') {
		scanner->last_tok.type = TOK_STRING;
		scanner->last_tok.str++;
		uint32_t old_pos = scanner->position;
		while (scanner_peek_char(scanner) != '\"')
		{
			if (!scanner_scan_char(scanner) || !scanner_peek_char(scanner))
				PANIC(scanner, ERROR_UNEXPECTED_TOK);
		}
		scanner->last_tok.length = scanner->position - old_pos;
		scanner_read_char(scanner);
		scanner_read_char(scanner);
	}
	else if (scanner->last_char == '\'') {
		scanner->last_tok.type = TOK_CHAR;
		scanner->last_tok.str++;
		uint32_t old_pos = scanner->position;
		if(!scanner_scan_char(scanner) || !scanner_peek_char(scanner))
			PANIC(scanner, ERROR_UNEXPECTED_TOK);
		scanner->last_tok.length = scanner->position - old_pos;
		if (!scanner_read_char(scanner) || scanner->last_char != '\'')
			PANIC(scanner, ERROR_UNEXPECTED_TOK);
		scanner_read_char(scanner);
	}
	else if (scanner->last_char == '$') {
		while (scanner_read_char(scanner) && scanner->last_char != '\n');
		return scanner_scan_tok(scanner);
	}
	else {
		switch (scanner->last_char)
		{
		case '#':
			RETURN(TOK_HASHTAG);
		case ';':
			RETURN(TOK_SEMICOLON);
		case '+':
			RETURN(TOK_ADD)
		case '-':
			RETURN(TOK_SUBTRACT)
		case '*':
			RETURN(TOK_MULTIPLY)
		case '/':
			RETURN(TOK_DIVIDE)
		case '%':
			RETURN(TOK_MODULO)
		case '^':
			RETURN(TOK_POWER)
		case '=':
			if (scanner_peek_char(scanner) == '=') {
				scanner_read_char(scanner);
				RETURN(TOK_EQUALS)
			}
			else
				RETURN(TOK_SET)
		case '!':
			if (scanner_peek_char(scanner) == '=') {
				scanner_read_char(scanner);
				RETURN(TOK_NOT_EQUAL)
			}
			else
				RETURN(TOK_NOT)
		case '>':
			if (scanner_peek_char(scanner) == '=') {
				scanner_read_char(scanner);
				RETURN(TOK_MORE_EQUAL);
			}
			else
				RETURN(TOK_MORE)
		case '<':
			if (scanner_peek_char(scanner) == '=') {
				scanner_read_char(scanner);
				RETURN(TOK_LESS_EQUAL)
			}
			else
				RETURN(TOK_LESS)
		case '&':
			if (scanner_peek_char(scanner) == '&') {
				scanner_read_char(scanner);
				RETURN(TOK_AND)
			}
			else
				PANIC(scanner, ERROR_UNEXPECTED_TOK)
		case '|':
			if (scanner_peek_char(scanner) == '|') {
				scanner_read_char(scanner);
				RETURN(TOK_OR)
			}
			else
				PANIC(scanner, ERROR_UNEXPECTED_TOK)
		case '{':
			RETURN(TOK_OPEN_BRACE);
		case '}':
			RETURN(TOK_CLOSE_BRACE);
		case '(':
			RETURN(TOK_OPEN_PAREN);
		case ')':
			RETURN(TOK_CLOSE_PAREN);
		case '[':
			RETURN(TOK_OPEN_BRACKET);
		case ']':
			RETURN(TOK_CLOSE_BRACKET);
		case ',':
			RETURN(TOK_COMMA);
		case '.':
			RETURN(TOK_PERIOD);
		case 0:
			RETURN(TOK_EOF);
		default:
			PANIC(scanner, ERROR_UNEXPECTED_TOK);
		}
		scanner_read_char(scanner);
	}
	return 1;
}
#undef RETURN

int init_multi_scanner(multi_scanner_t* scanner, const char* path) {
	scanner->visited_files = 0;
	scanner->current_file = 0;
	scanner->last_err = ERROR_NONE;
	ESCAPE_ON_FAIL(multi_scanner_visit(scanner, path));
	return 1;
}

void free_multi_scanner(multi_scanner_t* scanner) {
	for (uint_fast8_t i = 0; i < scanner->current_file; i++) {
		free(scanner->sources[i]);
		free(scanner->file_paths[i]);
	}
}

int multi_scanner_visit(multi_scanner_t* scanner, const char* file) {
	uint64_t id = hash(file);
	for (uint_fast8_t i = 0; i < scanner->visited_files; i++)
		if (id == scanner->visited_hashes[i])
			return 1;
	if (scanner->visited_files == 64 || scanner->current_file == 32)
		return 0;
	scanner->visited_hashes[scanner->visited_files++] = id;

	PANIC_ON_FAIL(scanner->sources[scanner->current_file] = file_read_source(file), scanner, ERROR_CANNOT_OPEN_FILE);
	PANIC_ON_FAIL(scanner->file_paths[scanner->current_file] = malloc((strlen(file) + 1) * sizeof(char)), scanner, ERROR_MEMORY);
	strcpy(scanner->file_paths[scanner->current_file], file);

	init_scanner(&scanner->scanners[scanner->current_file], scanner->sources[scanner->current_file], strlen(scanner->sources[scanner->current_file]));
	scanner_read_char(&scanner->scanners[scanner->current_file]);

	scanner->current_file++;
	return 1;
}

int multi_scanner_scan_tok(multi_scanner_t* scanner) {
	if (scanner->current_file) {
		PANIC_ON_FAIL(scanner_scan_tok(&scanner->scanners[scanner->current_file - 1]), scanner, scanner->scanners[scanner->current_file - 1].last_err);
		scanner->last_tok = scanner->scanners[scanner->current_file - 1].last_tok;
		if (scanner->last_tok.type == TOK_EOF) {
			free(scanner->file_paths[scanner->current_file - 1]);
			free(scanner->sources[scanner->current_file - 1]);
			--scanner->current_file;
			if (scanner->current_file)
				ESCAPE_ON_FAIL(multi_scanner_scan_tok(scanner));
		}
	}
	return 1;
}