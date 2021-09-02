#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "compiler.h"
#include "debug.h"

#define READ_ARG argv[current_arg++]
#define EXPECT_FLAG(FLAG) if(strcmp(READ_ARG, FLAG)) { exit(EXIT_FAILURE); }

int main(int argc, const char* argv[]) {
	int current_arg = 0;

	while (current_arg < argc)
	{
		const char* flag = READ_ARG;

		if (!strcmp(flag, "-info")) {
			
		}
		else if (!strcmp(flag, "-help")) {

		}
		else if (!strcmp(flag, "-cr")) {
			EXPECT_FLAG("-i");
			FILE* source = fopen(READ_ARG, "rb");
			
		}
		else if (!strcmp(flag, "-r")) {
			
		}
		else if (!strcmp(flag, "-c")) {
			
		}
		else {
			printf("Unexpected flag \"%s\".", flag);
			exit(EXIT_FAILURE);
		}
	}
	
	exit(EXIT_SUCCESS);
}