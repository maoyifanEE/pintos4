#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/vpage.h"
#include "vm/frame.h"
#include <bitmap.h>
#include "threads/synch.h"

struct bitmap *swap_bitmap;
struct lock swap_lock;

void swap_init(void);
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(void* kaddr);

#endif