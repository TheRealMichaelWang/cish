include "stdlib/io.sf";
include "stdlib/std.sf";

proc fact(int n) {
	if(n == 0)
		return 1;
	return n * thisproc(n - 1);
}

println(itos(fact(100)));