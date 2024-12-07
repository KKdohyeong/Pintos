#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/synch.h"

/* Partition that contains the file system. */
struct block *fs_device;
struct lock file_open_lock;


static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  lock_init(&file_open_lock);

  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open(const char *name) {
    //printf("[DEBUG] Attempting to open file: %s\n", name);

    // 락 획득
    lock_acquire(&file_open_lock);

    struct dir *dir = dir_open_root();
    struct inode *inode = NULL;

    if (dir == NULL) {
        //printf("[DEBUG] dir is NULL, cannot open file: %s\n", name);
        lock_release(&file_open_lock);
        return NULL;
    }

    // 파일 존재 여부 확인
    dir_lookup(dir, name, &inode);
    if (inode != NULL) {
        // 파일이 열려 있는 경우 참조 상태 확인
        struct file *opened_file = file_open(inode);
        if (opened_file != NULL && file_is_deny_write(opened_file)) {
            //printf("[DEBUG] File is already open with deny_write: %s\n", name);
        }
    }

    // 기존 동작
    struct file *opened_file = file_open(inode);
    dir_close(dir);

    lock_release(&file_open_lock);
    //printf("[DEBUG] File opened successfully: %s\n", name);
    return opened_file;
}


/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;
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
