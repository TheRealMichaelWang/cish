include "stdlib/buffer.csh";

record list<T> {
	array<T> elems = new T[15];
	int count = 0;
}

proc listAdd<T>(list<T> l, T elem) {
	if(l.count == #l.elems)
		l.elems = realloc<T>(l.elems, 5);
	if(l.count >= #l.elems)
		abort; $wtf?
	l.elems[l.count] = elem;
	l.count = l.count + 1;
}

proc listInsert<T>(list<T> l, int i, T elem) {
	if(l.count == #l.elems)
		l.elems = realloc<T>(l.elems, 5);
	memswap<T>(l.elems, i + 1, i, l.count - i);
	l.elems[i] = elem;
	l.count = l.count + 1;
}

proc listRemoveAt<T>(list<T> l, int i) => memswap<T>(l.elems, i, i + 1, (l.count = l.count - 1) - i)

proc listToArray<T>(list<T> l) {
	array<T> buf = new T[l.count];
	memcpy<T>(buf, l.elems, 0, 0, l.count);
	return buf;
}

proc listGet<T>(list<T> l, int i) => l.elems[i]
proc listSet<T>(list<T> l, int i, T elem) => l.elems[i] = elem

record searchableList<T> extends list<T> {
	readonly proc<bool, T, T> equals;
}

proc listIndexOf<T>(searchableList<T> l, T elem) {
	for(int i = 0; i < l.count; i++)
		if(l.equals(l.elems[i], elem))
			return i;
	return -1;
}

proc listRemove<T>(searchableList<T> l, T elem) {
	int i = listIndexOf<T>(l, elem);
	if(i < 0)
		return false;
	listRemoveAt<T>(l, i);
	return true;
}
