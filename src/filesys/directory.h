#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, size_t entry_cnt);
struct dir *dir_open (struct inode *);
struct dir *dir_root_open (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_inode_get (struct dir *);

/* Reading and writing. */
bool dir_search (const struct dir *, const char *name, struct inode **);
bool dir_add (struct dir *, const char *name, block_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_read (struct dir *, char name[NAME_MAX + 1]);
bool dir_empty_check(struct dir *,const char *);
void dir_init(struct dir*, struct dir*);
bool dir_name_check(const char*);

#endif 