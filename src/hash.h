#pragma once

#ifndef HASH_H
#define HASH_H

#include <stdint.h>

uint64_t hash_s(char* str, uint64_t len);
uint64_t hash(char* str);

#endif // !HASH_H