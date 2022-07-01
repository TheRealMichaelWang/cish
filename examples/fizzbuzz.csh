include "stdlib/io.csh";
include "stdlib/std.csh";

auto msgs = memset<array<char>>(new array<char>[15], 0, 15, "\n");
msgs[3] = msgs[6] = msgs[9] = msgs[12] = "fizz";
msgs[5] = msgs[10] = "buzz";
msgs[0] = "fizzbuzz";

for(int i = 0; i < 100; i++)
	println(msgs[i % 15]);	