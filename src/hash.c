#include <string.h>
#include "hash.h"

uint64_t hash_s(char* str, uint64_t len) {
    uint64_t hash = 5381;
    for (uint64_t i = 0; i < len; i++)
        hash = (hash << 5) + hash + str[i];
    return hash;
}

uint64_t hash(char* str) {
    return hash_s(str, strlen(str));
}