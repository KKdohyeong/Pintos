#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
char* getFileNamePointer(char *file_full_name);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void pushArgumentOnStack(const char* file_full_name, void **esp);
struct thread* get_child_thread(tid_t tid);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
bool expand_stack(void *addr);
bool verify_stack(void *fault_addr, void *esp);
#endif /* userprog/process.h */
