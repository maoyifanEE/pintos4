#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer_dir_cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
/* Number of direct block data pointer (128-5) */
#define DIRECT_BLOCK_ENTRIES 123 //(BLOCK_SECTOR_SIZE / sizeof(uint32_t) - 4)
/* Number of indirect block data pointer (128) */
#define INDIRECT_BLOCK_ENTRIES (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))

/* How to point disk block number. */
enum direct_type {
    DIRECT,
    INDIRECT,
    DOUBLE_INDIRECT,
    OVER_LIMIT
};

/* How to access a block address and save offset in index block. */
struct sector_location
{
    int direction_type;     /* Index for direct_t */ 
    uint32_t index1;    /* First index */
    uint32_t index2;    /* Second index for double indirect case */
};

/* index block. */
struct inode_indirect_block
{
    block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
    off_t length;                                          /* File size in bytes */
    uint32_t file_dir;                                     //
    unsigned magic;                                        /* Magic number */
    block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES]; /* Direct block data pointer */
    block_sector_t indirect_block_sec;                     /* Indirect block data pointer */
    block_sector_t double_indirect_block_sec;              /* Double indirect block data pointer */
};

/* In-memory inode. */
struct inode 
{
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_count;                       /* Number of openers. */
    bool remove;                       /* True if deleted, false otherwise. */
    bool write_deny_count;                 /* 0: writes ok, >0: deny writes. */
    struct lock lock_extend;            /* Semaphore lock. */
};

/* Reads inode from buffer cache and return it. */
static bool get_disk_inode (const struct inode *inode, struct inode_disk *inode_disk)
{
    return buffer_cache_read(inode->sector, inode_disk, 0, sizeof(struct inode_disk), 0);
}

/* Sets sector location structure. */
static void locate_byte (off_t pos, struct sector_location *sector_loc)
{
    off_t pos_sector = pos / BLOCK_SECTOR_SIZE;
    
    /* Direct index case */
    if (pos_sector < DIRECT_BLOCK_ENTRIES){
        sector_loc->direction_type = DIRECT;
        sector_loc->index1 = pos_sector;
    }
    /* Indirect index case */
    else if ((pos_sector -= DIRECT_BLOCK_ENTRIES) < INDIRECT_BLOCK_ENTRIES){
        sector_loc->direction_type = INDIRECT;
        sector_loc->index1 = pos_sector;
    }
    /* Double indirect index case */
    else if ((pos_sector -= INDIRECT_BLOCK_ENTRIES) < INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES){
        sector_loc->direction_type = DOUBLE_INDIRECT;
        sector_loc->index2 = pos_sector / INDIRECT_BLOCK_ENTRIES;
        sector_loc->index1 = pos_sector % INDIRECT_BLOCK_ENTRIES;
    }
    else{
        sector_loc->direction_type = OVER_LIMIT;
    }
}

/* Returns offset to bytes value. */
static inline off_t map_table_offset (int index)
{
    return (off_t)(index * sizeof(block_sector_t));
}

/* Updates new disk block number to inode_disk. */
static bool register_sector (struct inode_disk *inode_disk, 
                             block_sector_t new_sector, 
                             struct sector_location sector_loc){
    block_sector_t *blk_sec;
    struct inode_indirect_block *new_block, *new_block2; 
    bool checker = false;

    switch(sector_loc.direction_type)
    {
        case DIRECT:
            inode_disk->direct_map_table[sector_loc.index1] = new_sector;
            break;
        case INDIRECT:
            blk_sec = &inode_disk->indirect_block_sec;
            new_block2 = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
            if (new_block2 == NULL)
                goto rs_return_phase;
            if (*blk_sec == (block_sector_t) - 1) // first use case
            {
                if(!free_map_allocate(1, blk_sec))
                    goto rs_free_phase2;
                memset(new_block2, -1, sizeof(struct inode_indirect_block));
            }
            else // not first use case
            {
                if(!buffer_cache_read(*blk_sec, new_block2, 0, sizeof(struct inode_indirect_block), 0))
                    goto rs_free_phase2;
            }
            if(new_block2->map_table[sector_loc.index1] == (block_sector_t) - 1)
                new_block2->map_table[sector_loc.index1] = new_sector;
            if(!buffer_cache_write(*blk_sec, new_block2, 0, sizeof(struct inode_indirect_block), 0))
                goto rs_free_phase2;
            free(new_block2);
            break;
        case DOUBLE_INDIRECT:
            blk_sec = &inode_disk->double_indirect_block_sec;
            new_block2 = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
            if (new_block2 == NULL)
                goto rs_return_phase;
            if (*blk_sec == (block_sector_t) - 1) // first use case
            {
                if(!free_map_allocate(1, blk_sec))
                    goto rs_free_phase2;
                memset(new_block2, -1, sizeof(struct inode_indirect_block));
            }
            else // not first use case
            {
                if (!buffer_cache_read(*blk_sec, new_block2, 0, sizeof(struct inode_indirect_block), 0))
                    goto rs_free_phase2;
            }
            blk_sec = &new_block2->map_table[sector_loc.index2];
            if (*blk_sec == (block_sector_t) - 1)
                checker = true;
            new_block = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
            if (new_block == NULL)
                goto rs_free_phase2;
            if (*blk_sec == (block_sector_t) - 1) // first use case
            {
                if(!free_map_allocate(1, blk_sec))
                    goto rs_free_phase1;
                memset(new_block, -1, sizeof(struct inode_indirect_block));
            }
            else // not first use case
            {
                if (!buffer_cache_read(*blk_sec, new_block, 0, sizeof(struct inode_indirect_block), 0))
                    goto rs_free_phase1;
            }
            if (new_block->map_table[sector_loc.index1] == (block_sector_t) - 1)
                new_block->map_table[sector_loc.index1] = new_sector;
            if (checker && !buffer_cache_write(inode_disk->double_indirect_block_sec, new_block2, 0, sizeof(struct inode_indirect_block), 0)) // write double indirect table
                goto rs_free_phase1;
            if (!buffer_cache_write(*blk_sec, new_block, 0, sizeof(struct inode_indirect_block), 0)) // write indirect table
                goto rs_free_phase1;
            free(new_block);
            free(new_block2);
            break;
        default:
            return -1;
    }
    return 1;

rs_free_phase1:
    free(new_block);
rs_free_phase2:
    free(new_block2);
rs_return_phase:
    return false;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
    ASSERT (inode_disk != NULL);
    struct inode_indirect_block *ind_block;
    struct sector_location sector_loc;
    block_sector_t sector_type = inode_disk->indirect_block_sec;

    
    if (pos >= inode_disk->length)
    {
        return -1;
    }
    else{
        locate_byte(pos, &sector_loc);

           if(sector_loc.direction_type == DIRECT){
                sector_type = inode_disk->direct_map_table[sector_loc.index1];
                return sector_type;
            }
            else if(sector_loc.direction_type == INDIRECT){
                ind_block = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
                if (ind_block == NULL)
                    return -1;
                if (sector_type == (block_sector_t) - 1){
                    free(ind_block);
                    return -1;
                }
                if (!buffer_cache_read(sector_type, ind_block, 0, sizeof(struct inode_indirect_block), 0)){
                    free(ind_block);
                    return -1;
                }
                sector_type = ind_block->map_table[sector_loc.index1];
                free (ind_block);
                return sector_type;
            }
            else if(sector_loc.direction_type == DOUBLE_INDIRECT){
                ind_block = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
                if (ind_block == NULL)
                    return -1;
                if (inode_disk->double_indirect_block_sec == (block_sector_t) - 1){
                    free(ind_block);
                    return -1;
                }
                if (!buffer_cache_read(inode_disk->double_indirect_block_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0)){
                    free(ind_block);
                    return -1;
                }
                sector_type = ind_block->map_table[sector_loc.index2];
                if (sector_type == (block_sector_t) - 1){
                    free(ind_block);
                    return -1;
                }
                if (!buffer_cache_read(sector_type, ind_block, 0, sizeof(struct inode_indirect_block), 0)){
                    free(ind_block);
                    return -1;
                }
                sector_type = ind_block->map_table[sector_loc.index1];
                free (ind_block);
                return sector_type;
            }
            else{
                return -1;
            }
    }
    return 1;

}


/* Frees all data blocks in inode. */
static void inode_sectors_free (struct inode_disk *inode_disk){
    int i, j;
    struct inode_indirect_block ind_block, ind_block2;

    /* Direct index case */
    i = 0;
    while(i < DIRECT_BLOCK_ENTRIES)
    {
        if (inode_disk->direct_map_table[i] == (block_sector_t) - 1)
            break; 
        free_map_release(inode_disk->direct_map_table[i], 1);
        i++;
    }

    /* Check whether using indirect block */
    if(inode_disk->indirect_block_sec == (block_sector_t) - 1)
        return;

    /* Indirect index case */
    buffer_cache_read(inode_disk->indirect_block_sec, &ind_block, 0, sizeof(struct inode_indirect_block), 0);
    i = 0;
    while(i < INDIRECT_BLOCK_ENTRIES)
    {
        if(ind_block.map_table[i] == (block_sector_t) - 1)
            break;
        free_map_release(ind_block.map_table[i], 1);
        i++;
    }
    free_map_release(inode_disk->indirect_block_sec, 1);

    /* Check whether using double indirect block */
    if(inode_disk->double_indirect_block_sec == (block_sector_t) - 1)
        return;

    /* Double indirect index case */
    buffer_cache_read(inode_disk->double_indirect_block_sec, &ind_block, 0, sizeof(struct inode_indirect_block), 0);
    i = 0;
    while(i < INDIRECT_BLOCK_ENTRIES)
    { 
        i++;
        if (ind_block.map_table[i] == (block_sector_t) - 1)
            break;

        buffer_cache_read(ind_block.map_table[i], &ind_block2, 0, sizeof(struct inode_indirect_block), 0);
        for (j = 0; j < INDIRECT_BLOCK_ENTRIES; j++)
        {
            if (ind_block2.map_table[j] == (block_sector_t) - 1)
                break;
            free_map_release(ind_block2.map_table[j], 1);
        }
        free_map_release(ind_block.map_table[i], 1);
    }
    free_map_release(inode_disk->double_indirect_block_sec, 1);
}

//here

/* Allocates new disk blocks and updates inode. */
static bool inode_extend (struct inode_disk *inode_disk, off_t start_pos, off_t end_pos){
    static char zeroes[BLOCK_SECTOR_SIZE];
    struct sector_location sector_loc;
    block_sector_t sector_index;
    
    
    if (start_pos > end_pos)
        return -1;
    else if (start_pos == end_pos)
        return 1;
    else{
        inode_disk->length = end_pos;
        end_pos--;
        start_pos = start_pos / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE;
        end_pos = end_pos / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE;

        for (; start_pos <= end_pos; start_pos += BLOCK_SECTOR_SIZE)
        {
            sector_index = byte_to_sector(inode_disk, start_pos);
            if (sector_index == (block_sector_t) - 1){
                if(!free_map_allocate(1, &sector_index))
                    return false;
                locate_byte(start_pos, &sector_loc);
                if(!register_sector(inode_disk, sector_index, sector_loc))
                    return false;
                if(!buffer_cache_write(sector_index, zeroes, 0, BLOCK_SECTOR_SIZE, 0))
                    return false;
            }
        }
        return 1;
    }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t file_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL){
      return -1;
  }
  else{
      memset(disk_inode, -1, sizeof(struct inode_disk));
      disk_inode->file_dir = file_dir;
      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;
      if (!inode_extend(disk_inode, disk_inode->length, length))
      {
          free(disk_inode);
          return -1;
      }
      buffer_cache_write(sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0); 
      free (disk_inode);
      return 1;
  }
  return -1;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_count = 1;
  inode->write_deny_count = 0;
  inode->remove = false;
  lock_init(&inode->lock_extend);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_count++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  struct inode_disk inode_disk;
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_count == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->remove) 
      {
          get_disk_inode(inode, &inode_disk);
          inode_sectors_free(&inode_disk);
          free_map_release (inode->sector, 1);
      }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->remove = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  struct inode_disk inode_disk;

  lock_acquire(&inode->lock_extend);
  get_disk_inode(inode, &inode_disk);
  while (size > 0) 
  {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_index = byte_to_sector (&inode_disk, offset);
      off_t inode_length = inode_disk.length;
      lock_release(&inode->lock_extend);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0){
        lock_acquire(&inode->lock_extend); // exit trick
        break;
      }

      //
      bool read_done;
      read_done = buffer_cache_read(sector_index, buffer, sector_ofs, chunk_size, bytes_read);
      if(!read_done){
        lock_acquire(&inode->lock_extend); // exit trick
        break;
      }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;

      lock_acquire(&inode->lock_extend);
  }

  lock_release(&inode->lock_extend);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  struct inode_disk inode_disk;

  if (inode->write_deny_count)
    return 0;
  lock_acquire(&inode->lock_extend);//
  get_disk_inode(inode, &inode_disk);
  if(inode_disk.length < offset + size)
  {
      inode_extend(&inode_disk, inode_disk.length, offset + size);
      buffer_cache_write(inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  }
  while (size > 0) 
  {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_index = byte_to_sector (&inode_disk, offset);
      off_t inode_length = inode_disk.length;
      lock_release(&inode->lock_extend);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0){
          lock_acquire(&inode->lock_extend); // exit trick
          break;
      }
        //
      bool write_done;
      write_done = buffer_cache_write(sector_index, buffer, sector_ofs, chunk_size, bytes_written);
      if(!write_done){
        lock_acquire(&inode->lock_extend); // exit trick
        break;
      }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;

      lock_acquire(&inode->lock_extend);
  }

  lock_release(&inode->lock_extend);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_write_deny (struct inode *inode) 
{
  inode->write_deny_count++;
  ASSERT (inode->write_deny_count <= inode->open_count);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_write_deny() on the inode, before closing the inode. */
void
inode_write_allow (struct inode *inode) 
{
  ASSERT (inode->write_deny_count > 0);
  ASSERT (inode->write_deny_count <= inode->open_count);
  inode->write_deny_count--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk inode_disk;
  get_disk_inode(inode, &inode_disk);
  return inode_disk.length;
}

/* Returns whether the inode is a directory or a file. */
bool inode_file_dir (const struct inode *inode){

  struct inode_disk inode_disk;
  if (inode->remove || !get_disk_inode(inode, &inode_disk))
      return false;
  return inode_disk.file_dir;
}
