#include <stdlib.h>
#include "type.h"
#include "machine.h"

int init_machine(machine_t* machine, uint16_t stack_size, uint16_t frame_limit, uint16_t type_count) {
	machine->defined_sig_count = 0;
	ESCAPE_ON_FAIL(machine->stack = malloc(stack_size * sizeof(machine_reg_t)));
	ESCAPE_ON_FAIL(machine->defined_signatures = malloc((machine->alloced_sig_defs = 16) * sizeof(machine_type_sig_t)));
	ESCAPE_ON_FAIL(machine->type_table = calloc(type_count, sizeof(uint16_t)));
	return 1;
}

void free_machine(machine_t* machine) {
	free(machine->stack);
	free(machine->defined_signatures);
	free(machine->type_table);
}

machine_type_sig_t* new_type_sig(machine_t* machine) {
	if (machine->defined_sig_count == machine->alloced_sig_defs) {
		machine_type_sig_t* new_sigs = realloc(machine->defined_signatures, (machine->alloced_sig_defs += 10) * sizeof(machine_type_sig_t));
		ESCAPE_ON_FAIL(new_sigs);
		machine->defined_signatures = new_sigs;
	}
	return &machine->defined_signatures[machine->defined_sig_count++];
}