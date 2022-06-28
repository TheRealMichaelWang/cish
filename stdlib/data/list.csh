include "stdlib/buffer.csh";

record list<T> {
	array<T> elems = new T[15];
	int count = 0;
}

global readonly auto listAdd = proc<T>(list<T> l, T elem) {
	if(l.count == #l.elems)
		l.elems = realloc<T>(l.elems, l.count + 5);
	l.elems[l.count] = elem;
	l.count = l.count + 1;
};

global readonly auto listInsert = proc<T>(list<T> l, int i, T elem) {
	if(l.count == #l.elems)
		l.elems = realloc<T>(l.elems, l.count + 5);
	memswap<T>(l.elems, i + 1, i, l.count - i);
	l.elems[i] = elem;
	l.count = l.count + 1;
};

global readonly auto listRemoveAt = proc<T>(list<T> l, int i) => memswap<T>(l.elems, i, i + 1, (l.count = l.count - 1) - i);

global readonly auto listToArray = proc<T>(list<T> l) {
	array<T> buf = new T[l.count];
	memcpy<T>(buf, l.elems, 0, 0, l.count);
	return buf;
};

global readonly auto listGet = proc<T>(list<T> l, int i) => l.elems[i];
global readonly auto listSet = proc<T>(list<T> l, int i, T elem) => l.elems[i] = elem;

record searchableList<T> extends list<T> {
	readonly proc<bool, T, T> equals;
};

global readonly auto listIndexOf = proc<T>(searchableList<T> l, T elem) {
	for(int i = 0; i < l.count; i++)
		if(l.equals(l.elems[i], elem))
			return i;
	return -1;
};

global readonly auto listRemove = proc<T>(searchableList<T> l, T elem) {
	int i = listIndexOf(l, elem);
	if(i < 0)
		return false;
	listRemoveAt<T>(l, i);
	return true;
};
