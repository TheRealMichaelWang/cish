include "stdlib/data/set.csh";
include "stdlib/math/primes.csh";
include "stdlib/std.csh";
include "stdlib/io.csh";

set<int> a = new set<int> {
	hasher = proc(int i) => i;
};

for(int i = 0; i < 10000; i++)
	if(isPrime(i))
		setAdd<int>(a, i);

for(int i = 0; i < 10000; i++)
	if(setFind<int>(a, i))
		println(itos(i));