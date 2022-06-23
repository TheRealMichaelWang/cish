global readonly auto memset = proc<T>(array<T> a, int start, int length, T val) {
	for(int i = 0; i < length; i++)
		a[i + start] = val;
	return a;
};

global readonly auto memsetLazy = proc<T>(array<T> a, int start, int length, proc<T> lazyVal) {
	for(int i = 0; i < length; i++)
		a[i + start] = lazyVal();
	return a;
};

global readonly auto memcpy = proc<T>(array<T> dest, array<T> src, int destOffset, int srcOffset, int length) {
	for(int i = 0; i < length; i++)
		dest[i + destOffset] = src[i + srcOffset];
};

global readonly auto memswap = proc<T>(array<T> a, int dest, int src, int length) {
	if(length == 0)
		return;

	array<T> tempbuf = new T[length];
	memcpy<T>(tempbuf, a, 0, src, length);
	memcpy<T>(a, tempbuf, dest, 0, length);
};

global readonly auto memcmp = proc<T>(array<T> a, array<T> b, proc<int, T, T> compare) {
	if(#a != #b)
		return #a - #b;

	for(int i = 0; i < #a; i++) {
		auto res = compare(a[i], b[i]);
		if(res != 0)
			return res;
	}
	abort;
};

global readonly auto memcat = proc<T>(array<T> a, array<T> b) {
	auto newBuf = new T[#a + #b];
	memcpy<T>(newBuf, a, 0, 0, #a);
	memcpy<T>(newBuf, b, #a, 0, #b);
	return newBuf;
};

global readonly auto realloc = proc<T>(array<T> oldBuf, int newSize) {
	array<T> newBuf = oldBuf;
	newBuf = foreign[18](newSize);
	return newBuf;
};