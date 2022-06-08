#include "filesys/buffer_dir_cache.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "lib/string.h"

#define BUFFER_CACHE_MAX 64

struct list buffer_cache_list;
int buffer_cache_count;
struct list_elem *buffer_cache_clk;
static struct list_elem* get_next_buffer_cache_clk(void);

bool buffer_cache_full_check(void){
    if(buffer_cache_count <  BUFFER_CACHE_MAX){
        return false;
    }
    else{
        return true;
    }
}

void buffer_cache_init(void){
    lock_init(&buffer_cache_lock);
    list_init(&buffer_cache_list);
    buffer_cache_count = 0;
    buffer_cache_clk = NULL;
}
void buffer_cache_list_add(struct buffer_cache* buffer_cache){
    buffer_cache_count++;
    list_push_back(&buffer_cache_list, &buffer_cache->elem);
}

void buffer_cache_list_del(struct buffer_cache* buffer_cache){
    if (buffer_cache_clk == &buffer_cache->elem){
        buffer_cache_clk = get_next_buffer_cache_clk();
    }
    buffer_cache_count--;
    list_remove (&buffer_cache->elem);
}

bool buffer_cache_read(block_sector_t sector_index, void *buffer, int sector_ofs, int chunk_size, off_t bytes_read){
    
    struct buffer_cache * buffer_cache;
    bool lock = false;
    bool flag;

    flag = lock_held_by_current_thread(&buffer_cache_lock);
    if(!flag){
        lock_acquire(&buffer_cache_lock);
        lock = true;
    }

    flag = (buffer_cache = buffer_cache_search(sector_index));
    if( flag != NULL){
        buffer_cache->access = true;
        memcpy(buffer+bytes_read, buffer_cache->buffer_cache_pos+sector_ofs, chunk_size);
    }else{ 
        if(buffer_cache_full_check()){
            buffer_cache_evict();
        }
        buffer_cache = (struct buffer_cache *)malloc(sizeof(struct buffer_cache));
        if( buffer_cache == NULL){
            lock_release(&buffer_cache_lock);
            return false;
        }
        buffer_cache_list_add(buffer_cache);
        buffer_cache->sector = sector_index;
        buffer_cache->dirty = false;
        buffer_cache->access = false;
        buffer_cache->occupy =true;

        buffer_cache->buffer_cache_pos = malloc(BLOCK_SECTOR_SIZE);
        if( buffer_cache->buffer_cache_pos == NULL){
            lock_release(&buffer_cache_lock);
            return false;
        }

        block_read(filesys_device, sector_index, buffer_cache->buffer_cache_pos);
        memcpy(buffer+bytes_read, buffer_cache->buffer_cache_pos+sector_ofs, chunk_size);
    }

    buffer_cache->occupy = false;
    if(lock){
        lock_release(&buffer_cache_lock);
    }
    return true;
}


bool buffer_cache_write(block_sector_t sector_index, const void *buffer, int sector_ofs, int chunk_size, off_t bytes_written){//
    
    struct buffer_cache * buffer_cache;
    lock_acquire(&buffer_cache_lock);

    bool flag;//
    
    flag = (buffer_cache = buffer_cache_search(sector_index));//
    if( flag != NULL){ 
        buffer_cache->dirty = true;
        buffer_cache->access = true;
        memcpy(buffer_cache->buffer_cache_pos+sector_ofs, buffer+bytes_written, chunk_size);

    }else{ 
        if(buffer_cache_full_check()){
            buffer_cache_evict();
        }
        buffer_cache = (struct buffer_cache *)malloc(sizeof(struct buffer_cache));
        if( buffer_cache == NULL){
            lock_release(&buffer_cache_lock);
            return false;
        }
        buffer_cache_list_add(buffer_cache);
        buffer_cache->sector = sector_index;
        buffer_cache->dirty = true;
        buffer_cache->access = false;
        buffer_cache->occupy = true;

        buffer_cache->buffer_cache_pos = malloc(BLOCK_SECTOR_SIZE);
        if( buffer_cache->buffer_cache_pos == NULL){
            lock_release(&buffer_cache_lock);
            return false;
        }

        flag = sector_ofs > 0;//
        if ( flag || chunk_size >= BLOCK_SECTOR_SIZE-sector_ofs){
            memset (buffer_cache->buffer_cache_pos, 0, BLOCK_SECTOR_SIZE);
        }else{
            block_read (filesys_device, sector_index, buffer_cache->buffer_cache_pos);  
        }
        
        memcpy(buffer_cache->buffer_cache_pos+sector_ofs, buffer+bytes_written, chunk_size);
    }
    buffer_cache->occupy = false;
    
    lock_release(&buffer_cache_lock);
    return true;

}

void buffer_cache_check(void){
    buffer_cache_fill_up();//
    buffer_cache_free_all();//
}

struct buffer_cache * buffer_cache_search(block_sector_t sector){

    struct list_elem *e ;
    struct buffer_cache *buffer_cache;

    for( e = list_begin(&buffer_cache_list); e != list_end(&buffer_cache_list); e = list_next(e)){
        buffer_cache= list_entry(e, struct buffer_cache, elem);
        if( buffer_cache->sector == sector){
            return buffer_cache;
        }
    }

    return NULL;
}

static struct list_elem* get_next_buffer_cache_clk(void){
    struct list_elem *retval;

    if (list_empty(&buffer_cache_list)){
        retval = NULL;
    }
    else if (buffer_cache_clk == NULL){
        retval = list_begin(&buffer_cache_list);
    }
    else if (buffer_cache_clk == list_end(&buffer_cache_list)){
        retval = list_begin(&buffer_cache_list);
    }
    else if ( list_next(buffer_cache_clk) == list_end(&buffer_cache_list)){
        retval = list_begin(&buffer_cache_list); 
    }
    else{
        retval = list_next(buffer_cache_clk);
    }
    
    return retval;
}

bool buffer_cache_access_check(struct buffer_cache *buffer_cache){
    if(buffer_cache->access){
        return true;
    }
    else{
        return false;
    }
}

void buffer_cache_set_access(struct buffer_cache *buffer_cache, bool access){
    buffer_cache->access = access;
}

bool buffer_cache_dirty_check(struct buffer_cache *buffer_cache){
    if(buffer_cache->dirty){
        return true;
    }
    else{
        return false;
    }
}

void  buffer_cache_evict(void){
    struct buffer_cache * buffer_cache;


    buffer_cache_clk = get_next_buffer_cache_clk();
    buffer_cache = list_entry(buffer_cache_clk, struct buffer_cache, elem); 

    while(buffer_cache->occupy || buffer_cache_access_check(buffer_cache)){
        buffer_cache_set_access(buffer_cache, false);
        buffer_cache_clk = get_next_buffer_cache_clk();
        buffer_cache = list_entry(buffer_cache_clk, struct buffer_cache, elem); 
    }

    if(buffer_cache_dirty_check(buffer_cache)){
        buffer_cache_fill(buffer_cache);
    }
    
    buffer_cache_list_del(buffer_cache);

    free(buffer_cache->buffer_cache_pos);
    free(buffer_cache);

}

void buffer_cache_fill(struct buffer_cache *flush){
    block_write(filesys_device, flush->sector, flush->buffer_cache_pos);
    flush->dirty = false;
}

void buffer_cache_fill_up(void){

    struct list_elem *e ;
    struct buffer_cache *buffer_cache;

    lock_acquire(&buffer_cache_lock);

    for( e = list_begin(&buffer_cache_list); e != list_end(&buffer_cache_list); e = list_next(e)){
        buffer_cache= list_entry(e, struct buffer_cache, elem);
        if(buffer_cache_dirty_check(buffer_cache)){
            buffer_cache_fill(buffer_cache);
        }
    }

    lock_release(&buffer_cache_lock);

}

void buffer_cache_free_all(void){

    struct list_elem *e ;
    struct list_elem *next_e;
    struct buffer_cache *buffer_cache;

    lock_acquire(&buffer_cache_lock);

    for( e = list_begin(&buffer_cache_list); e != list_end(&buffer_cache_list); ){
        next_e = list_next(e);
        buffer_cache= list_entry(e, struct buffer_cache, elem);
        buffer_cache_list_del(buffer_cache);
        free(buffer_cache->buffer_cache_pos);
        free(buffer_cache);
        e = next_e;
    }
    buffer_cache_count = 0;
    buffer_cache_clk = NULL;

    lock_release(&buffer_cache_lock);

}

static bool dir_cache_less_func(const struct hash_elem *a, const struct hash_elem * b, void* aux UNUSED){

    struct dir_entry_cache * dir_cache_a = hash_entry(a, struct dir_entry_cache, elem);
    struct dir_entry_cache * dir_cache_b = hash_entry(b, struct dir_entry_cache, elem);
    
    return strcmp(dir_cache_a->path, dir_cache_b->path) < 0 ? true : false;
}

static unsigned dir_cache_hash_func(const struct hash_elem *e, void* aux UNUSED){

    struct dir_entry_cache * dir_cache = hash_entry(e, struct dir_entry_cache, elem);
    return hash_string((const char*)dir_cache->path);

}

void dir_cache_free(struct hash_elem * e, void * aux UNUSED){
    
    struct dir_entry_cache * dir_cache = hash_entry(e, struct dir_entry_cache, elem);
    
    free(dir_cache->path);
    free(dir_cache);
}

void dir_cache_init(void){
    lock_init(&dir_cache_lock); 
    hash_init(&dir_entry_cache_hash, dir_cache_hash_func, dir_cache_less_func, NULL);



}
bool dir_cache_insert(const char *name, block_sector_t inumber){
    bool success = false;

    struct dir_entry_cache * dir_cache = malloc(sizeof(struct dir_entry_cache));
    dir_cache->path =(char*) malloc(strlen(name)+1);
    strlcpy(dir_cache->path, name, strlen(name)+1);
    dir_cache->inumber = inumber;

   
    lock_acquire(&dir_cache_lock); 
    if(hash_insert(&dir_entry_cache_hash, &dir_cache->elem)==NULL){
        success = true;
    }
    lock_release(&dir_cache_lock);
    if(success){
        return true;
    }
    else{
        return false;
    }
}



bool dir_cache_delete(struct hash* dir_cache_hash, struct dir_entry_cache *dir_cache){
    bool success = false;
    lock_acquire(&dir_cache_lock); 
    
    if( hash_delete(dir_cache_hash, &dir_cache->elem) !=NULL){
        success= true;
        free(dir_cache->path);
        free(dir_cache);
    
    }
    lock_release(&dir_cache_lock);
    if(success){
        return true;
    }
    else{
        return false;
    }
}


struct dir_entry_cache * dir_cache_find_1(const char* path){
    
    struct hash_elem *e;
    struct dir_entry_cache  dir_cache;
    struct dir_entry_cache  *ret_dir_cache;

    dir_cache.path = path;
    lock_acquire(&dir_cache_lock); 
    e = hash_find(&dir_entry_cache_hash,&dir_cache.elem);
    if( e == NULL){
        ret_dir_cache = NULL;
    }else{
        ret_dir_cache = hash_entry(e, struct dir_entry_cache, elem);
    }
    lock_release(&dir_cache_lock); 

    return ret_dir_cache;
}

struct dir_entry_cache * dir_cache_find_2(const char* path, char* file_name){
    
    struct hash_elem *e;
    char * token;
    struct dir_entry_cache dir_cache;

    char * temp_name = malloc(strlen(path)+1);

    strlcpy(temp_name, path, strlen(path)+1);

    token = strrchr(temp_name, '/');
    
    *token = '\0';
    dir_cache.path = temp_name;

    struct dir_entry_cache * ret_dir_cache = dir_cache_find_1(dir_cache.path);
    *token = '/';
    if(ret_dir_cache != NULL){
        strlcpy(file_name, token+1, strlen(token));
    }
    
    free(temp_name);
    return ret_dir_cache;
}

void dir_cache_close(struct hash* dir_cache_hash){
    hash_destroy(dir_cache_hash, dir_cache_free);
}