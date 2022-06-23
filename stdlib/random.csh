global readonly auto randirange = proc(int start, int stop) return int {
	return (foreign[10] % (stop - start)) + stop;
};

global readonly auto randbool = proc() return bool {
	return foreign[10] % 2 == 0;
};