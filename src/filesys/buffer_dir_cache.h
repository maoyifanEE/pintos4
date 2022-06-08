#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "lib/kernel/hash.h"

struct lock buffer_cache_lock;
struct hash dir_entry_cache_hash;
struct lock dir_cache_lock;

struct buffer_cache{
    block_sector_t sector;
    bool dirty;
    bool access;
    bool occupy;
    void* buffer_cache_pos;
    struct list_elem elem;
};

struct dir_entry_cache{
    char* path;
    block_sector_t inumber;
    struct hash_elem elem;
};


void buffer_cache_init(void);
void buffer_cache_check(void);
bool buffer_cache_read(block_sector_t, void *, int, int, off_t);
bool buffer_cache_write(block_sector_t, const void *, int, int, off_t);
struct buffer_cache * buffer_cache_search(block_sector_t sector);
void buffer_cache_evict(void);
void buffer_cache_fill(struct buffer_cache *flush);
void buffer_cache_fill_up(void);
void buffer_cache_free_all(void);
bool buffer_cache_full_check(void);
void buffer_cache_list_add(struct buffer_cache *);
void buffer_cache_list_del(struct buffer_cache *);
bool buffer_cache_access_check(struct buffer_cache *);
void buffer_cache_set_access(struct buffer_cache *,bool);
bool buffer_cache_dirty_check(struct buffer_cache *);



void dir_cache_free(struct hash_elem * e, void * aux );
void dir_cache_init(void);
bool dir_cache_insert(const char*, block_sector_t);
bool dir_cache_delete(struct hash* dir_cache_hash, struct dir_entry_cache *dir_cache);
void dir_cache_close(struct hash* dir_cache_hash);
struct dir_entry_cache * dir_cache_find_1(const char* path);
struct dir_entry_cache * dir_cache_find_2(const char* path, char*);
#endif 