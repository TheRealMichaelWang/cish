include "stdlib/buffer.sf";

global readonly auto swapElems = proc<T>(array<T> buf, int i, int j) {
	T temp = buf[i];
	buf[i] = buf[j];
	buf[j] = temp;
};

global readonly auto sort = proc<T>(array<T> a, proc<int, T, T> compare) {
	bool unsorted = true;

	while(unsorted) {
		unsorted = false;
	
		for(int i = 1; i < #a; i++)
			if(compare(a[i], a[i - 1]) < 0) {
				swapElems<T>(a, i, i-1);
				unsorted = true;
			}
	}

	return;
};

global readonly auto quicksort = proc<T>(array<T> a, proc<int, T, T> compare) {
	readonly auto recsort = proc<T>(array<T> a, proc<int, T, T> compare, int low, int high) {
		readonly auto partition = proc<T>(array<T> a, proc<int, T, T> compare, int low, int high) {
			T pivot = a[high];
			int i = (low - 1);

			for(int j = low; j < high; j++)
				if(compare(a[j], pivot) < 0)
					swapElems<T>(a, ++i, j);
		
			swapElems<T>(a, ++i, high);
			return i;
		};

		if(low >= high or low < 0)
			return;

		int pivot = partition<T>(a, compare, low, high);
		thisproc<T>(a, compare, low, pivot - 1);
		thisproc<T>(a, compare, pivot + 1, high);
	};
	
	recsort<T>(a, compare, 0, #a - 1);
};

global readonly auto isSorted = proc<T>(array<T> a, proc<int, T, T> compare) {
	for(int i = 1; i < #a; i++)
		if(compare(a[i], a[i-1]) < 0)
			return false;
	return true;
};

global readonly auto search = proc<T>(array<T> a, T key, proc<int, T, T> compare) {
	if(!isSorted<T>(a, compare))
		sort<T>(a, compare);

	readonly auto binSearch = proc<T>(array<T> a, T key, proc<int, T, T> compare, int start, int stop) {
		if(stop - start == 1)
			return false;
		
		int mid = start + (stop - start) / 2;
		int res = compare(key, a[mid]);

		if(res < 0) 
			return thisproc<T>(a, key, compare, start, mid);
		else if(res < 0)
			return thisproc<T>(a, key, compare, mid, stop);
		else
			return true;
	};

	return binSearch<T>(a, key, compare, 0, #a);
};
