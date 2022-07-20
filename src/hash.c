#include <string.h>
#include "hash.h"

uint64_t hash_s(const char* str, uint64_t len) {
    uint64_t hash_num = 5381;
    for (uint64_t i = 0; i < len; i++)
        hash_num = (hash_num << 5) + hash_num + str[i];
    return hash_num;
}

uint64_t hash(const char* str) {
    return hash_s(str, strlen(str));
}