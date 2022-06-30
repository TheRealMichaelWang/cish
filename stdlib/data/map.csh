include "stdlib/buffer.sf";
include "stdlib/std.sf";

abstract record mapBucket<K, V>;

final record emptyMapBucket<K, V> extends mapBucket<K, V>;

final record keyValuePair<K, V> extends mapBucket<K, V> {
	readonly K key;
	readonly V value;

	readonly int keyHash;
}

record map<K, V> {
	array<mapBucket<K, V>> buckets = memset<mapBucket<K, V>>(new mapBucket<K, V>[50], 0, 50, new emptyMapBucket<K, V>);
	proc<int, K> hasher;
}

proc mapEmplace<K, V>(map<K, V> m, K key, V value) {
	proc emplace<K, V>(map<K, V> m, keyValuePair<K, V> pair) {
		for(int i = pair.keyHash % #m.buckets; i < #m.buckets; i++)
			if(m.buckets[i] is emptyMapBucket<any, any>)
				return m.buckets[i] = pair;
			else {
				auto kvBucket = dynamic_cast<keyValuePair<K, V>>(m.buckets[i]);
				if(kvBucket.keyHash == pair.keyHash)
					return m.buckets[i] = pair;
			}

		auto oldBuckets = m.buckets;
		m.buckets = memset<mapBucket<K, V>>(new mapBucket<K, V>[#oldBuckets + 5], 0, #oldBuckets + 5, new emptyMapBucket<K, V>);
		for(int i = 0; i < #oldBuckets; i++)
			if(oldBuckets[i] is keyValuePair<K, V>)
				thisproc<K, V>(m, dynamic_cast<keyValuePair<K, V>>(oldBuckets[i]));
		return thisproc<K, V>(m, pair);
	}

	emplace<K, V>(m, new keyValuePair<K, V> {
		key = key;
		value = value;
		keyHash = m.hasher(key);
	});
}

final record keyNotFound<K, V> extends error<V> {
	readonly K key;
	msg = "Key not found.";
}

proc mapFind<K, V>(map<K, V> m, K key) return fallible<V> {
	int keyHash = m.hasher(key);
	for(int i = keyHash % #m.buckets; i < #m.buckets; i++)
		if(m.buckets[i] is keyValuePair<K, V>) {
			auto kvBucket = dynamic_cast<keyValuePair<K, V>>(m.buckets[i]);
			if(kvBucket.keyHash == keyHash)
				return new success<V> {
					result = kvBucket.value;
				};
		}

	return new keyNotFound<K, V> {
		key = key;
	};
}