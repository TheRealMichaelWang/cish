include "stdlib/buffer.cish";

proc millerRabin(int p, int iterations) {
	$returns (a * b) % c
	proc mulmod(int a, int b, int c) {
		int mutB = b;
		int x = 1; int y = a % c;
		while(mutB > 0) {
			if(mutB % 2 == 1)
				x = (x + y) % c;
			y = (y * 2) % c;
			mutB = mutB / 2;
		}
		return x % c;
	}

	if(p < 2 or (p != 2 and p % 2 == 0))
		return false;

	int s = p - 1;
	while(s % 2 == 0)
		s = s / 2;

	for(int i = 0; i < iterations; i++) {
		int a = foreign[10] % (p - 1) + 1;
		int temp = s;

		int mod = mulmod(a, temp, p);
		while(temp != p-1 and mod != 1 and mod != p-1) {
			mod = mulmod(mod, mod, p);
			temp = temp * 2;
		}

		if(mod != p-1 and temp % 2 == 0)
			return false;
	}
	return true;
}

global int lowPrimeLimit = 1000;
global array<bool> lowPrimeBuffer = memset<bool>(new bool[lowPrimeLimit + 1], 0, lowPrimeLimit + 1, true);
lowPrimeBuffer[0] = lowPrimeBuffer[1] = false;

for(int i = 2; i < lowPrimeLimit; i++) {
	if(lowPrimeBuffer[i])
		for(int j = i * i; j <= lowPrimeLimit; j = j + i)
			lowPrimeBuffer[j] = false;
}

proc isPrime(int n) {
	if(n < lowPrimeLimit) 
		return lowPrimeBuffer[n];
	return millerRabin(n, 20);
}
