#pragma once

#ifndef HASH_H
#define HASH_H

#include <stdint.h>

const uint64_t hash_s(const char* str, const uint64_t len);
const uint64_t hash(const char* str);

#endif // !HASH_H