#include "userprog/usermem.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

#define PAGE_ALIGN 0xFFFFF000

bool access_ok(void *userptr, bool write) {
    struct thread *cur = thread_current();
    if (!is_user_vaddr(userptr)) {
        return false;
    }
    /*
    if ((pagedir_get_page(cur->pagedir, (const void *)userptr) != NULL)) {
        if (write) {
            return pagedir_is_writable(cur->pagedir, (const void *)userptr);
        }
        else {
            return true;
        }
    }
    else {
        return false;
    }
    */
   return true;
}

void fault_region_enter() {
    thread_current()->kernel_fault_allowed = true;
}

void fault_region_exit() {
    thread_current()->kernel_fault_allowed = false;
}

bool is_in_fault_region() {
    return thread_current()->kernel_fault_allowed;
}

size_t copy_from_user(void *kaddr, void *uaddr, size_t length) {
    size_t return_value;
    uint32_t _uaddr = (uint32_t)uaddr, first_pg, last_pg, iter_pg;
    fault_region_enter();
    /* integer overflow */
    if (_uaddr + length <= _uaddr) {
        return_value = -1;
        goto done;
    }
    
    first_pg = pg_round_down(_uaddr);
    last_pg = pg_round_down(_uaddr + length -1);
    for (iter_pg = first_pg; iter_pg <= last_pg; iter_pg += PGSIZE) {
        if (!access_ok((void *)iter_pg, false)) {
            return_value = -1;
            goto done;
        }
    }
    
    memcpy(kaddr, uaddr, length);
    return_value = length;
done:
    fault_region_exit();
    return return_value;
}

size_t copy_to_user(void *uaddr, void *kaddr, size_t length) {
    size_t return_value;
    uint32_t _uaddr = (uint32_t)uaddr, first_pg, last_pg, iter_pg;
    fault_region_enter();
    /* integer overflow */
    if (_uaddr + length < _uaddr) {
        return_value = -1;
        goto done;
    }
    
    first_pg = _uaddr & PAGE_ALIGN;
    last_pg = (_uaddr + length) & PAGE_ALIGN;
    for (iter_pg = first_pg; iter_pg <= last_pg; iter_pg += PGSIZE) {
        if (!access_ok((void *)iter_pg, true)) {
            return_value = -1;
            goto done;
        }
    }
    
    memcpy(uaddr, kaddr, length);
    return_value = length;
done:
    fault_region_exit();
    return return_value;
}