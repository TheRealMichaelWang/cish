include "stdlib/buffer.csh";

abstract record setBucket;
	final record emptySetBucket extends setBucket;
	final record elemSetBucket extends setBucket {
		readonly int hash;
	}

record set<T> {
	array<setBucket> buckets = memset<setBucket>(new setBucket[15], 0, 15, new emptySetBucket);
	readonly proc<int, T> hasher;
}

proc setAdd<T>(set<T> s, T elem) {
	proc insert<T>(set<T> s, int hash) {
		for(int i = hash % #s.buckets; i < #s.buckets; i++)
			if(s.buckets[i] is emptySetBucket) {
				s.buckets[i] = new elemSetBucket {
					hash = hash;
				};
				return true;
			}
			else if(dynamic_cast<elemSetBucket>(s.buckets[i]).hash == hash)
				return false;
		auto oldBuckets = s.buckets;
		s.buckets = memset<setBucket>(new setBucket[#oldBuckets + 5], 0, #oldBuckets + 5, new emptySetBucket);
		for(int i = 0; i < #oldBuckets; i++)
			if(oldBuckets[i] is elemSetBucket)
				thisproc<T>(s, dynamic_cast<elemSetBucket>(oldBuckets[i]).hash);
		return thisproc<T>(s, hash);
	}
	return insert<T>(s, s.hasher(elem));
}

proc setRemove<T>(set<T> s, T elem) {
	int hash = s.hasher(elem);
	for(int i = hash % #s.buckets; i < #s.buckets; i++)
		if(s.buckets[i] is elemSetBucket) {
			if(dynamic_cast<elemSetBucket>(s.buckets[i]).hash == hash) {
				s.buckets[i] = new emptySetBucket;
				return true;
			}
		}
		else return false;
	return false;
}

proc setFind<T>(set<T> s, T elem) {
	int hash = s.hasher(elem);
	for(int i = hash % #s.buckets; i < #s.buckets; i++)
		if(s.buckets[i] is elemSetBucket)
		if(dynamic_cast<elemSetBucket>(s.buckets[i]).hash == hash)
			return true;
	return false;
}