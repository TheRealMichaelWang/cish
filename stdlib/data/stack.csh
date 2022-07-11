include "stdlib/std.csh";
include "stdlib/buffer.csh";

final record stack<T> {
	array<T> elems = new T[15];
	int count = 0;
}

proc stackPush<T>(stack<T> s, T elem) {
	if(s.count == #s.elems)
		s.elems = realloc<T>(s.elems, 5);
	s.elems[s.count] = elem;
	s.count = s.count + 1;
}

final record emptyStackError<T> extends error<T> {
	msg = "Operation couldn't be performed because the stack is empty";
}

proc stackPop<T>(stack<T> s) return fallible<T> {
	if(s.count == 0)
		return new emptyStackError<T>;
	return new success<T> {
		result = s.elems[s.count = s.count - 1];
	};
}