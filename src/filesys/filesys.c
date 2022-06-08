#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer_dir_cache.h"
#include "threads/thread.h"
#include "threads/malloc.h"

//mao finished

/* Partition that contains the file system. */
struct block *filesys_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_device = block_get_role (BLOCK_FILESYS);
  if (filesys_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  buffer_cache_init();

  if (format) 
    do_format ();

  free_map_open ();

  struct dir * init_root = dir_root_open();
  thread_current()->current_dir = init_root;//
  dir_init(init_root, init_root);
  dir_cache_init();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  buffer_cache_check();//
  dir_cache_close(&dir_entry_cache_hash);//
}


bool path_type_check(const char *name){//
    int abosule = 1;
    int related = 0;
    
    if(name[0] == '/'){
        return abosule;
    }
    else if( name == NULL || strlen(name) == 0){
        return related;
    }
    else{
      return 0;
    }
}

int file_level(const char* name){
    char* p  = name;
    int count =0;
    while(*p != '\0'){
      if(*p == '/'){
            count++;
        }
      p++;
    }
    return count;
}

struct dir* path_parse(const char *path_name, char *file_name){
    
    struct dir* dir;
    char *token, *next_token, *save_ptr;
    struct inode *inode;
    if(thread_current()->current_dir == NULL){
        return NULL;
    }

    if(strlen(path_name) == 0){
        return NULL;
    }
    if(path_name == NULL){
      return NULL;
    }
    if(file_name == NULL){
      return NULL;
    }

    char * temp_name = calloc(1, strlen(path_name)+1);
    char * free_name = temp_name;

    strlcpy(temp_name,path_name, strlen(path_name)+1);
    
    if(path_name[0] != '/'){ //relative  
        dir = dir_reopen(thread_current()->current_dir);
    }else{   //absolute
       dir = dir_root_open();
    }

    token = strtok_r(temp_name, "/", &save_ptr);
    next_token = strtok_r(NULL, "/", &save_ptr);

    if(token !=NULL && next_token == NULL){
        if(strlen(token) > NAME_MAX +1){
            dir_close(dir);
            free(free_name);
            return NULL;
        }
    }
    while(token != NULL && next_token != NULL){
        if(strlen(token) >NAME_MAX+1 || strlen(next_token) > NAME_MAX +1){
            dir_close(dir);
            free(free_name);
            return NULL;
        }
        if(!dir_search(dir,token,&inode)){
            dir_close(dir);
            free(free_name);
            return NULL;
        }
        dir_close(dir);
        if(!inode_file_dir(inode)){
            free(free_name);
            return NULL;
        }
        dir = dir_open(inode); 

        strlcpy(token, next_token, strlen(next_token)+1);
        next_token = strtok_r(NULL, "/", &save_ptr);
    }


    if( token != NULL ) {
      strlcpy(file_name, token, strlen(token)+1);
    }else {
      strlcpy(file_name, ".", 2);
    }
    free(free_name);
    return dir;
}




/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char* file_name = calloc(1, NAME_MAX+1);
  struct dir *dir = path_parse (name, file_name);
  bool create = (dir != NULL && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, 0)
                  && dir_add (dir, file_name, inode_sector));
  if (!create){
    if(inode_sector != 0){
      free_map_release (inode_sector, 1);
    }
  } 
  free(file_name);
  dir_close (dir);

  return create;
}

bool filesys_create_dir (const char *name){
  if(strcmp(name, "")==0){
    return false;
  }
  block_sector_t inode_sector = 0;
  char* dir_name = calloc(1, NAME_MAX +1 );
  struct dir *dir;
  struct dir *child_dir ;
  struct inode *inode;

  struct dir_entry_cache * dir_cache;
  bool cached = false;

  if(!path_type_check(name)){
    dir = path_parse (name, dir_name);
  }else{
   if((dir_cache = dir_cache_find_1(name)) != NULL){
            free(dir_name);
            return false;
      }else{
          if(file_level(name) >=2 &&(dir_cache = dir_cache_find_2(name,dir_name)) != NULL){
                dir = dir_open(inode_open(dir_cache->inumber));
                cached = true;
          }else{
                dir = path_parse (name, dir_name);
        }
    }
  }
  
  bool flag = (dir != NULL && free_map_allocate (1, &inode_sector)
                  && dir_create (inode_sector, 16)
                  && dir_add (dir, dir_name, inode_sector));
  if (!flag && inode_sector != 0) {
    free_map_release (inode_sector, 1);
  }else{
    dir_search(dir, dir_name, &inode); 
    child_dir = dir_open(inode);
    dir_init(dir, child_dir);
    dir_close(child_dir);
    
    if(path_type_check(name)){
        if(!dir_cache_insert(name,inode_sector)){
            flag = false;
        }
    }
  }

  free(dir_name);
  dir_close (dir);

  return flag;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{

  if(strcmp(name, "")==0){
    return NULL;
  }
  char* file_name = calloc(1, NAME_MAX +1 );
  struct dir *dir;
  struct inode *inode = NULL;

  struct dir_entry_cache * dir_cache;

  if(!path_type_check(name)){
    dir = path_parse (name, file_name);
  }else{
      if((dir_cache = dir_cache_find_1(name)) != NULL){
            free(file_name);
            return file_open(inode_open(dir_cache->inumber));
      }else{
          if(file_level(name) >=2 &&(dir_cache = dir_cache_find_2(name,file_name)) != NULL){
                dir = dir_open(inode_open(dir_cache->inumber));
          }else{
                dir = path_parse (name, file_name);
          }
      }
  }

  if (dir != NULL){
    dir_search (dir, file_name, &inode);
      if(path_type_check(name)){
          if(!dir_cache_insert(name,inode_get_inumber(inode))){
            dir_close (dir);
            free(file_name);
            return NULL;

          }
      }
  }
  dir_close (dir);
  free(file_name);

  return file_open (inode);
}
 

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char* file_name = calloc(1, NAME_MAX +1 );
  struct dir *dir;
  struct dir_entry_cache * dir_cache;
  struct dir_entry_cache * dir_cache_parent;
  bool cached = false;

  if(!path_type_check(name)){
    dir = path_parse (name, file_name);
  }else{
    if((dir_cache = dir_cache_find_1(name)) != NULL){
          cached = true;
          if(file_level(name) >=2 &&(dir_cache_parent = dir_cache_find_2(name,file_name)) != NULL){
                dir = dir_open(inode_open(dir_cache_parent->inumber));
          }else {
            dir = path_parse (name, file_name);
          }
      }else{
        dir = path_parse (name, file_name);   
      }
  }
  bool remove = (dir != NULL) && dir_remove(dir, file_name);
  
  if(remove && cached){
    if(!dir_cache_delete(&dir_entry_cache_hash,dir_cache)){
        remove = false;
    }
  }
  free(file_name);
  dir_close (dir); 

  return remove;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
//stop!!!
//stop!!!
//stop!!!

bool fliesys_children_dir(const char *name){
    char* dir_name = calloc(1, NAME_MAX+1);
    struct dir* dir = path_parse(name,dir_name);
    struct inode *inode = NULL;
    struct dir* children_dir;
    bool flag = false;

    if(dir != NULL){
        if(!dir_search(dir,dir_name, &inode)){
          free(dir_name);
          return flag;
        }
        children_dir = dir_open(inode);
        if(thread_current()->current_dir !=NULL){
            dir_close(thread_current()->current_dir);
        }
        thread_current()->current_dir = children_dir;
        flag = true;
    }
    free(dir_name);
    return flag;
}