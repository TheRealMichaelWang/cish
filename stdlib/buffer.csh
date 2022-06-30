proc memset<T>(array<T> a, int start, int length, T val) {
	for(int i = 0; i < length; i++)
		a[i + start] = val;
	return a;
}

proc memsetLazy<T>(array<T> a, int start, int length, proc<T> lazyVal) {
	for(int i = 0; i < length; i++)
		a[i + start] = lazyVal();
	return a;
}

proc memcpy<T>(array<T> dest, array<T> src, int destOffset, int srcOffset, int length) {
	for(int i = 0; i < length; i++)
		dest[i + destOffset] = src[i + srcOffset];
}

proc memswap<T>(array<T> a, int dest, int src, int length) {
	if(length == 0)
		return;

	array<T> tempbuf = new T[length];
	memcpy<T>(tempbuf, a, 0, src, length);
	memcpy<T>(a, tempbuf, dest, 0, length);
}

proc memcmp<T>(array<T> a, array<T> b, proc<int, T, T> compare, T zero) {
	for(int i = 0; i < #a; i++) {
		if(i == #b)
			return compare(a[i], zero);

		auto res = compare(a[i], b[i]);
		if(res != 0)
			return res;
	}
	return 0;
}

proc memcat<T>(array<T> a, array<T> b) {
	auto newBuf = new T[#a + #b];
	memcpy<T>(newBuf, a, 0, 0, #a);
	memcpy<T>(newBuf, b, #a, 0, #b);
	return newBuf;
}

proc realloc<T>(array<T> oldBuf, int newSize) {
	array<T> newBuf = oldBuf;
	newBuf = foreign[18](newSize);
	return newBuf;
}