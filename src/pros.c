#include "pros.h"

void pros_emit_info(FILE* file_out, const char* input_file) {
	fputs("\nvoid on_center_button() {\n\t", file_out);
	fprintf(file_out, "robot_log_cstr(\"Program: %s\");", input_file);
	fputs("\n}", file_out);
}

void pros_emit_events(FILE* file_out) {
	static const char* event_names[] = {
		"initialize",
		"autonomous",
		"disabled",
		"competition_initialize",
		"opcontrol"
	};

	static const char* mode_names[] = {
		"OP_MODE_INIT",
		"OP_MODE_AUTON",
		"OP_MODE_DISABLED",
		"OP_MODE_COMP_INIT",
		"OP_MODE_OP_CONTROL"
	};

	static const char* log_msgs[] = {
		"running auton...",
		"disabled",
		"comp initializing...",
		"running operator control..."
	};

	fputs("\n\nstatic volatile int ran = 0;"
			"\nstatic volatile int inited = 0;", file_out);
	for (int i = 0; i < 5; i++) {
		fprintf(file_out, "\n\nvoid %s() {\n\top_mode = %s;\n", event_names[i], mode_names[i]);
		if (i == 0) {//generate initialize code
			fputs(
				"#ifndef ROBOSIM\n"
				"\tlcd_initialize();\n"
				"\tlcd_register_btn1_cb(on_center_button);\n"
				"\trobot_log_cstr(\"initializing...\");\n"
				"#endif\n"
				"\tif(!init_all()) {\n\t\treturn;\n\t}\n"
				"\tinited = 1;\n",
				file_out
			);
		}
		else if (i == 1 || i == 4) { //generate run code
			fprintf(file_out, "\trobot_log_cstr(\"%s\");\n", log_msgs[i - 1]);
			fputs(
				"\twhile(!inited) {} //wait for initialze() to finish\n"
				"\tif(ran) {\n"
				"\t\trobot_log_cstr(\"Cannot start program, already ran.\");\n"
				"\t\treturn;\n"
				"\t}\n"
				"\tran = 1;\n"
				"\tif(!run()) {\n"
				"\t\trobot_log_cstr(\"Runtime Error:\");\n"
				"\t\trobot_log_cstr(error_names[last_err]);\n\t}\n"
				"\tfree_runtime();\n",
				file_out
			);
		}
		fputc('}', file_out);
	}
}