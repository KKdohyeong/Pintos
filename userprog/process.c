#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


/*
1. 내 파일 이름이 echo x로 되어 있는 것이 문제
2. 이것들을 문자열마다 다 분절을 해서 저장을 한다. echo, x, ~~~, ~~~ 이렇게
3. 
*/


//mmap_file의 vme_list에 연결된 모든 vm_entry들을 제거
void do_munmap(struct mmap_file* mmap_file)
{
	//mmap_file의 vme_list에 연결된 모든 vm_entry들을 제거
	struct list_elem *e;
	for(e=list_begin(&mmap_file->vme_list);e!=list_end(&mmap_file->vme_list); )
	{

		//다음 주소 백업해둠
		struct list_elem *next_e=list_next(e);

		struct vm_entry *vme=list_entry(e, struct vm_entry, mmap_elem);
		//vm_entry가 가리키는 가상 주소에 대한 물리 페이지가 존재하고 dirty하면 디스크에 메모리 내용을 기록
		if(vme->is_loaded && pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)) {
			//lock_acquire(&filesys_lock);
			file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
			//lock_release(&filesys_lock);
		}
		vme->is_loaded = false;
		//vme_list에서 vme 제거
		list_remove(e);

		//페이지 테이블 entry 제거
		delete_vme(&thread_current()->vm, vme);
		//다음 주소 복원
		e=next_e;
	}


	//mmap_file 제거
	list_remove(&mmap_file->elem);
	free(mmap_file);
}
 
char* getFileNamePointer(char *file_full_name){
    char *token, *save_ptr;
    char *file_name;
    token = strtok_r(file_full_name, " ", &save_ptr);
    //printf("token is %s\n", token);
    if(token!=NULL){
      size_t length = strlen(token) + 1;
      file_name = malloc(length);
      strlcpy(file_name, token, length);
      return file_name;
    }
    else{
      return NULL;
    }
}

struct thread* get_child_thread(tid_t tid) {
    struct thread *cur = thread_current();
    struct list_elem *e;

    for (e = list_begin(&(cur->child_threads)); e != list_end(&(cur->child_threads)); e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, child_thread_elem);
        if (t->tid == tid) {
            return t;
        }
    }
    return NULL;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char *file_name_copy;
  char *exec_name;
  char *save_ptr;
  tid_t tid;

  printf("[process_execute] Starting process_execute with file_name: %s\n", file_name);


  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    printf("[process_execute] Failed to allocate memory for fn_copy.\n");
    return TID_ERROR;
  }
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Make another copy of FILE_NAME for parsing. */
  file_name_copy = malloc(strlen(file_name) + 1);
  if (file_name_copy == NULL) {
    printf("[process_execute] Failed to allocate memory for file_name_copy.\n");
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);

  /* Extract the executable name from file_name_copy */
  exec_name = strtok_r(file_name_copy, " ", &save_ptr);
  if (exec_name == NULL) {
    printf("[process_execute] Failed to extract exec_name from file_name_copy.\n");
    palloc_free_page(fn_copy);
    free(file_name_copy);
    return TID_ERROR;
  }
  printf("[process_execute] Extracted exec_name: %s\n", exec_name);

  /* Check if the executable file exists */
  struct file *file = filesys_open(exec_name);
  if (file == NULL) {
    printf("[process_execute] File not found: %s\n", exec_name);
    palloc_free_page(fn_copy);
    free(file_name_copy);
    return TID_ERROR;
  }
  //printf("[process_execute] File found: %s\n", exec_name);
  file_close(file);
  free(file_name_copy);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR) {
    printf("[process_execute] Failed to create thread for %s.\n", file_name);
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  printf("[process_execute] Thread created with TID: %d\n", tid);

  struct thread *child_thread = get_child_thread(tid);
  if (child_thread == NULL) {

    printf("[process_execute] Failed to find child thread for TID: %d.\n", tid);
    return -1;
  }
  sema_down(&(child_thread->load_sema));


  /*for(elem=list_begin(&thread_current()->child_threads);elem!=list_end(&thread_current()->child_threads);elem=list_next(elem)){
    t = list_entry(elem, struct thread, child_thread_elem);
    if(t->load_success==false){
      return process_wait(tid);
    }
  }
*/
  printf("[process_execute] Process execution complete for TID: %d\n", tid);
  return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
	struct thread *current_thread=thread_current();
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

	vm_init(&(current_thread->vm));

  
  success = load (file_name, &if_.eip, &if_.esp);


  /* 로드 결과를 부모에게 알림 */
  printf("here?\n");
  thread_current()->load_success = success;
  printf("here??\n");
  sema_up(&(thread_current()->load_sema));
  printf("here???\n");
  palloc_free_page (file_name);
  printf("here????\n");

  if (!success) {
        printf("load fail \n");
        exit (-1);
    }

  /* If load failed, quit. */

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  printf("[DEBUG] Jumping to user program: eip = %p, esp = %p\n", if_.eip, if_.esp);
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing.
   
   

child process의 pid를 기다린다. 이건 우리가 배운 세마포어나 뮤텍스로 기다리게 하자.
retrieves the child’s exit status. 자식의 exit status를 찾아온다.

child process가 termianted된 상황에서 부모가 wait을 부르는건 가능한 상황이다.
하지만 이 상황에서도 커널은 부모가 child's exit status를 가져올 수 있도록 해야한다.
or learn that the child was terminated by the kernel 이 말이 뭔말이냐?

왠지 exit에서 thread를 종료하는 설정만 하라고 하고 메모리 해제 뭐 부모 쓰레드에서의 제거 등등은 하지 말라. 그러면 wait에서 부모에서
자식 쓰레드 접근할 때 없어진것에 접근하게 되어서 이상하게 된다.

내가 기다리는 pid를 검색해서 끝나는것을 세마포어로 기다려야한다.

1. 자식 리스트를 순회한다.
 1-1 순회하다가 내가 찾는 tid를 발견한다. ->
 - list는 head와 끝 elem 저장
 - list_elem으로 이동
 1-2 해당 tid가 exit인지 확인한다. 
 1-3 자식 thread의 sema_down(exit_sema)를 통해 up이 될 때가지 기다린다
 1-3 thread가 exit이 되면서 sema_up을 할 것이라 이를 통해 알 수 있다.
 1-4 부모 쓰레드는 자식 쓰레드를 리스트에서 지운다.
 1-5 부모 쓰레드는 자식 쓰레드가 점유하는 메모리들을 싹 정리?해야한다?
 1-6 자식 쓰레드는 
 * 여기서의 중요한 점은 exit을 했을 때 부모의 리스트에서 아예 지워버리면 내가 찾는 tid를 못찾을 수도 있다는 것이다.
 * 그래서 실제처럼 종료랑 실제 메모리랑 등등을 압수해가는 것은 나중의 일이다.?


 return은 자식의 exit status이다.

** 부모가 자식에 대해서 필요한것
1. thread 그 자체
2. list_elem이 존재해야 한다. 그래야 찾을 수 있다.
3. exit_sema가 존재해야 한다.

Q palloc_free_page를할까마띾


    */
int process_wait (tid_t child_tid) 
{

    struct thread* running_thread = thread_current();
    struct list_elem* child_elem;
    struct thread* child_thread;
    printf("process_wait start tid is %d\n", child_tid);

    child_thread = get_child_thread(child_tid);

    if (child_thread == NULL) {
        printf("process_wait: Cannot find child with TID %d\n", child_tid);
        return -1;
    }
    printf("waiting start\n");
    sema_down(&(child_thread->exit_sema)); // Wait for child to exit
    printf("wait success\n");
    int exit_status = child_thread->exit_status; // Retrieve exit status before signaling

    list_remove(&(child_thread->child_thread_elem)); // Remove from child list

    sema_up(&(child_thread->memory_sema)); // Allow child to proceed
    //printf("exit stats값이 : %d\n", exit_status);
    return exit_status; // Safe to return the stored exit status
        
}


/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  printf("%s: exit(%d)\n", thread_name(), cur->exit_status);
  
  struct thread* child_thread;  
	struct list_elem *e;
	for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list);) {
		//다음 elem 백업
		struct list_elem *next_e = list_next(e);

		struct mmap_file *m_file = list_entry(e, struct mmap_file, elem);
		do_munmap(m_file);

		//다음 elem 복원
		e = next_e;
	}

  if(cur->exec_file !=NULL){
        file_allow_write(cur->exec_file);
        file_close(cur->exec_file);
        cur->exec_file = NULL;    
  }
  for(int i=3; i<128; i++){
       if (cur->file_descriptor[i] != NULL) {
            file_close(cur->file_descriptor[i]);
            cur->file_descriptor[i] = NULL;
        }
  }
  vm_destroy(&cur->vm);


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */


/*
1. argv_num을 구한다
2. 명령어를 분절해서 argv[i]에 넣는다
3. argv[i]를 스택에 넣고 그 스택의 주소를 저장한다.
4. align을 해서 스택을 재정비한다
5. 빈 공간 4를 넣고 명령어 주소를 스택에 넣는다
6. 명령어 주소 스택에 넣은 그 최초 시작 주소를 저장하고 스택에 넣는다.
7. argv_num을 스택에 넣는다
8. 맨 마지막에 return address 0을 넣는다. 사실 이게 뭔지 모르겟다 잘.
*/


void print_stack(void *esp, int stack_size) {
    printf("[DEBUG] Stack content from %p:\n", esp);
    uint32_t *ptr = (uint32_t *)esp;
    for (int i = 0; i < stack_size / 4; i++) { // 4바이트씩 읽기
        printf("  [%p]: 0x%08x\n", ptr, *ptr);
        ptr++;
    }
}





void pushArgumentOnStack(const char* file_full_name, void **esp){
  char *token, *save_ptr;
  char *token1, *save_ptr1;
  char file_full_name_copy[100];
  strlcpy(file_full_name_copy, file_full_name, strlen(file_full_name)+1);
  int argv_num = 0;
  char **argv;
  int *argv_length;
  char **argv_address;
  int total_argv_length = 0;
  //printf("copy right?%s\n\n", file_full_name_copy);
  // 1. argv_num을 구한다.
  for (token1 = strtok_r (file_full_name_copy, " ", &save_ptr1); token1 != NULL; token1 = strtok_r (NULL, " ", &save_ptr1)){
        argv_num++;
   }

  argv_length = (int *)malloc(sizeof(int) * argv_num);
  argv = (char **)malloc(sizeof(char *) * argv_num);
  argv_address = (char **)malloc(sizeof(char *) * argv_num);

  //printf("file full name is %s and argv_num is %d\n", file_full_name, argv_num);

  //2. 명령어를 분절해서 argv에 넣고 스택에 바로 넣는다. 그리고 그 스택의 주소를 저장한다.
  // 나중에 strlcpy함수를 보면 문자열 길이 +1을 하면 알아서 '\n'을 넣어준다.
  //argv는 **라서 어떤 문자열들의 주소를 기다리고, token은 받은 filㅁ들의 시작 주소 위치들을 받아오는 것이다. 그래서 이렇게 저장하면 돼

  int i=0;
   for (token = strtok_r (file_full_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)){
      argv[i] = token;
      argv_length[i] = strlen(token)+1;

      //실제 저장
      i++;
   }

   for(int i=argv_num-1; i>=0; i--){
      *esp = *esp - argv_length[i];
      argv_address[i] = *esp;
      strlcpy(*esp, argv[i], argv_length[i]);
      //printf("token is %s save str is %s and lengh is %d and address is %p\n",token,  argv[i], argv_length[i], argv_address[i]);

   }

   //4번 align을 하자.
   for(int i=0; i<argv_num; i++){
      total_argv_length += argv_length[i];
   }
   int align = 0;
   if(align%4){
      align =  4 - (total_argv_length%4);
   }
   *esp = *esp - align;
  // printf("change address is %p\n", *esp);
   //printf("finish and argv num is %d and after file full is %s\n", argv_num, file_full_name);

   //5번 맨 위에는 4바이트의 빈 공간을 넣고 나머지에는 인자들의 주소를 넣자.
    //4바이트씩 데이터를 넣을거라 uint32로 한다.
   *esp = *esp-4;
    **((uint32_t**)esp)=0;
    for(int i=argv_num-1; i>=0; i--){
      *esp -=4;
      **((uint32_t**)esp)=(uint32_t)argv_address[i];
      
    }

  //6. 주소의 시작점
  *esp-=4;
  **((uint32_t**)esp)=*esp+4;
 
  //7. 인자 갯수
  *esp-=4;
  **((uint32_t**)esp)=argv_num;
 
  //8. return address
  *esp-=4;
  **((uint32_t**)esp)=0;

  free(argv);
  free(argv_address);
  free(argv_length);
}


/*
현재 파일을 실행하면서 이 쓰레드에 이 파일을 실행한다고 남긴다. 이를 그리고 write_lock같은 것을 거는 것이다.


*/

bool
load (const char *file_full_name, void (**eip) (void), void **esp) 
{
  ASSERT(file_full_name != NULL);

  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char *file_name = NULL;
  char *file_name_copy = NULL;

  // 동적 메모리 할당
  size_t name_length = strlen(file_full_name) + 1; // NULL 문자 포함
  file_name_copy = malloc(name_length);
  if (file_name_copy == NULL) {
    printf("load: Memory allocation failed for file_name_copy.\n");
    goto done;
  }
  strlcpy(file_name_copy, file_full_name, name_length);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
 
  /* 파일 이름 추출 */
  file_name = (char*)getFileNamePointer(file_full_name);
  if (file_name == NULL) {
    printf("load: Failed to extract file name.\n");
    goto done;
  }
  strlcpy(t->name, file_name, sizeof(t->name));

  /* 파일 열기 */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  t->exec_file = file;
  file_deny_write(file);
  printf("load에서 여기까진 아마 문제 없을거야\n");
  /* ELF 헤더 읽기 및 검증 */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  printf("start esp here is %p\n", esp);
  /* 프로그램 헤더 읽기 */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable)){
                                  printf("load_segment 실패\n");
                                  goto done;

                                 }
            }
          else
            goto done;
          break;
        }
    }
  printf("start esp before setup_stack is %p\n", esp);

  /* 스택 설정 */
  if (!setup_stack (esp)){
    printf("setup stack fail\n");
    goto done;

  }
  printf("start esp before push is %p\n", esp);  
  /* 인자 스택에 푸시 */
  pushArgumentOnStack(file_name_copy, esp);
  printf("here???\n");
  /* 엔트리 포인트 설정 */
  *eip = (void (*) (void)) ehdr.e_entry;
  printf("after esp is %p\n", esp);
  print_stack(esp, 128); // 64바이트 범위 출력
  success = true;

 done:
  /* 동적 메모리 해제 */
  if (file_name_copy != NULL) {
    free(file_name_copy);
  }
  if (file_name != NULL) {
    free(file_name);
  }
  return success;  
}


/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          printf("install page to frame fail\n");
          palloc_free_page (kpage);
          return false; 
        }

      // Debugging: Print page information
      printf("Page loaded: vaddr = %p, writable = %d\n", upage, writable);

      //vm entry 생성(malloc 사용)
      struct vm_entry *vme = malloc(sizeof(struct vm_entry));
      if (vme == NULL) {
        printf("Failed to allocate memory for vm_entry\n");
        return false;
      }

      //vm_entry 멤버들 설정
      vme->type = VM_BIN;
      vme->vaddr = upage;
      vme->writable = writable;
      vme->is_loaded = false;
      vme->file = file;
      vme->offset = ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;

      //insert_vme()함수를 사용해서 생성한 vm_entry를 해시 테이블에 추가
      if (!insert_vme(&thread_current()->vm, vme)) {
        printf("Failed to insert vm_entry into hash table\n");
        free(vme);
        return false;
      }

      // Debugging: Print vm_entry information
      printf("vm_entry created: vaddr = %p, offset = %d, read_bytes = %zu, zero_bytes = %zu, writable = %d\n",
             vme->vaddr, (int)vme->offset, vme->read_bytes, vme->zero_bytes, vme->writable);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
    struct page *kpage;
    void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
    bool success = false;

    // Allocate a page for the stack
    kpage = alloc_page(PAL_USER | PAL_ZERO);
    if (kpage == NULL) {
        printf("[DEBUG] Failed to allocate stack page for upage: %p\n", upage);
        return false;
    }
    printf("[DEBUG] Stack page allocated: upage = %p, kpage = %p\n", upage, kpage->kaddr);

    // Install the page into the page table
    if (install_page(upage, kpage->kaddr, true)) {
        *esp = PHYS_BASE;
        printf("[DEBUG] Stack pointer initialized: esp = %p\n", *esp);

        // Create vm_entry for the stack
        struct vm_entry *vme = malloc(sizeof(struct vm_entry));
        if (vme == NULL) {
            printf("[DEBUG] Failed to allocate vm_entry for stack at upage: %p\n", upage);
            free_page(kpage->kaddr);
            return false;
        }
        vme->type = VM_ANON;
        vme->vaddr = upage;
        vme->writable = true;
        vme->is_loaded = true;
        kpage->vme = vme;

        // Insert vm_entry into the hash table
        if (!insert_vme(&(thread_current()->vm), vme)) {
            printf("[DEBUG] Failed to insert vm_entry into hash table: upage = %p\n", upage);
            free_page(kpage->kaddr);
            free(vme);
            return false;
        }
        printf("[DEBUG] vm_entry created and inserted: upage = %p\n", upage);
        success = true;
    } else {
        printf("[DEBUG] Failed to install stack page: upage = %p, kpage = %p\n", upage, kpage->kaddr);
        free_page(kpage->kaddr);
        return false;
    }
    return success;
}


/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


//파일 객체를 File Descriptor 테이블에 추가

//파일 디스크립터 값에 해당하는 파일 객체 반환
struct file *process_get_file(int fd)
{
	struct thread *t=thread_current();
	//파일 디스크립터에 해당하는 파일 객체를 리턴
	//없을 시 NULL 리턴(처음 thread 초기화 및 파일 삭제시 NULL로 설정하도록 할 것이므로 그냥 반환하면 됨)
	return t->file_descriptor[fd];
}

//파일 디스크립터에 해당하는 파일을 닫음
void process_close_file(int fd)
{
	struct thread* t=thread_current();
	//file descriptor에 해당하는 파일을 닫음
	file_close(t->file_descriptor[fd]);
	//파일 디스크립터 테이블의 해당 entry를 초기화
	t->file_descriptor[fd]=NULL;
}


//addr 주소를 포함하도록 스택을 확장
bool expand_stack(void *addr) {
    // alloc_page()를 통해 메모리 할당
    struct page *kpage = alloc_page(PAL_USER | PAL_ZERO);
    if (kpage == NULL) {
        printf("[DEBUG] Failed to allocate page for addr: %p\n", addr);
        return false;
    }
    printf("[DEBUG] Page allocated: kpage = %p, for addr = %p\n", kpage->kaddr, addr);

    // vm_entry 할당 및 초기화
    struct vm_entry *vme = malloc(sizeof(struct vm_entry));
    if (vme == NULL) {
        printf("[DEBUG] Failed to allocate vm_entry for addr: %p\n", addr);
        free_page(kpage->kaddr);
        return false;
    }
    vme->type = VM_ANON;
    vme->vaddr = pg_round_down(addr); // 페이지 크기에 맞게 주소를 내림
    vme->writable = true;
    vme->is_loaded = true;
    printf("[DEBUG] vm_entry created: vaddr = %p, type = %d\n", vme->vaddr, vme->type);

    // 해시 테이블에 vm_entry 추가
    if (!insert_vme(&thread_current()->vm, vme)) {
        printf("[DEBUG] Failed to insert vm_entry into vm hash table.\n");
        free_page(kpage->kaddr);
        free(vme);
        return false;
    }
    printf("[DEBUG] vm_entry inserted into hash table: vaddr = %p\n", vme->vaddr);

    // install_page() 호출하여 페이지 테이블 설정
    kpage->vme = vme;
    if (!install_page(vme->vaddr, kpage->kaddr, vme->writable)) {
        printf("[DEBUG] install_page failed: vaddr = %p, kpage = %p\n", vme->vaddr, kpage->kaddr);
        free_page(kpage->kaddr);
        free(vme);
        return false;
    }
    printf("[DEBUG] Page installed: vaddr = %p, kpage = %p\n", vme->vaddr, kpage->kaddr);

    // 성공 시 true를 반환
    return true;
}


bool verify_stack(void*fault_addr, void *esp)
{
	void *maximum_limit = PHYS_BASE-8*1024*1024;
	//esp 주소가 포함되어 있는지 확인하는 함수
	return is_user_vaddr(pg_round_down(fault_addr)) && fault_addr>=esp - 32 && fault_addr >= maximum_limit;
}

bool handle_mm_fault(struct vm_entry *vme)
{

	//palloc_get_page()를 이용해서 물리 메모리 할당 그런데 이게 alloc이 ㄱ꽉차서 못얻으면 어떻게 한다는거지?
	struct page *kpage = alloc_page (PAL_USER);
	kpage->vme=vme;
	//switch문으로 vm_entry의 타입별 처리
	switch(vme->type)
	{
		case VM_BIN:
			//VM_BIN일 경우 load_file 함수를 이용해서 물리 메모리에 로드
			if(!load_file(kpage->kaddr, vme))
			{
				free_page(kpage->kaddr);
				return false;
			}
			break;
		case VM_FILE:
			//vm_FILE시 데이터를 로드할 수 있도록 수정
			if(!load_file(kpage->kaddr, vme))
			{
				free_page(kpage->kaddr);
				return false;
			}
			break;
		case VM_ANON:
			//swap_in하는 코드 삽입
			swap_in(vme->swap_slot, kpage->kaddr);
			break;
	}

	//install_page를 이용해서 물리페이지와 가상 페이지 맵핑
	if (!install_page (vme->vaddr, kpage->kaddr, vme->writable))
	{
		free_page (kpage->kaddr);
		return false;
	}
	//로드에 성공하였으면 vme->is_loaded를 true로 바꾸어줌
	vme->is_loaded=true;

	//로드 성공여부 반환
	return true;

}
