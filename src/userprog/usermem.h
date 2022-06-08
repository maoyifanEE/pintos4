#include <stddef.h>
#include <stdio.h>

// validate a user memory address
bool access_ok(void *uaddr, bool write);
void fault_region_enter();
void fault_region_exit();
bool is_in_fault_region();
size_t copy_from_user(void *kaddr, void *uaddr, size_t length);
size_t copy_to_user(void *uaddr, void *kaddr, size_t length);
