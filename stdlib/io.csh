include "stdlib/buffer.csh";

$prints a string onto the console
proc print(array<char> str)
	for(int i = 0; i < #str; i++)
		foreign[8](str[i]);

$prints a string onto the console, with a newline at the end
proc println(array<char> str) {
	print(str);
	foreign[8]('\n');
}

$puts a char
proc putChar(char c)
	foreign[8](c);

$reads a line of input
proc input() {
	auto buffer = new char[4096];

	int i = 0;
	for(char last_scanned = '\0'; last_scanned != '\n'; last_scanned = foreign[9])
		buffer[i++] = last_scanned;

	array<char> output = new char[--i];
	memcpy<char>(output, buffer, 0, 0, i);
	return output;
}
proc beep()
	foreign[8](\a);
