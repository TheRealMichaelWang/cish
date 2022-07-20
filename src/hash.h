#pragma once

#ifndef HASH_H
#define HASH_H

#include <stdint.h>

uint64_t hash_s(const char* str, uint64_t len);
uint64_t hash(const char* str);

#endif // !HASH_H