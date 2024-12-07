#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "vm/page.h"


static void syscall_handler (struct intr_frame *);

struct lock file_lock;



/*
일단 우리 pintos는 단일프로세스/단일쓰레드를 지향하는 것 같다. 그래서 pid tid구분을 일단 하지 말아보자..? 나중에 필요하면 뭐 더 해보자.
*/

void
syscall_init (void) 
{

  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct vm_entry * check_address(void *addr, void *esp)
{
	//포인터가 가리키는 주소가 유저영역의 주소인지 확인
	//잘못된 접근인 경우 프로세스 종료
	if(0x8048000>addr || 0xc0000000<=addr) {
		exit(-1);
	}

	//addr이 vm_entry에 존재하면 vm_entry를 반환하도록 코드 수정
	//find_Vme()사용
	struct vm_entry * vme= find_vme(addr);
	if(vme==NULL)
	{
		if(!verify_stack(addr, esp))
			exit(-1);
		expand_stack(addr);
		vme=find_vme(addr);
	}
	return vme;
}

/*
1번은 user providedd pointer를 먼저 검증하고 dereference하라는 것이다.
이 방법은 userprog/pagedir.c랑 threads/vaddr.h를 참고해서 하라고 한다.
이걸 여기서는 추천한다 한다. 간단해서? 인듯.
2번방식은 뭐 주소만 검사하고 나머지 오류핸들링은 page fault쪽 exception.c에서 하라는데 이건 복잡한데 더 빨라서 실제 사용한다한다. 난 안쓸래
*/
/*void check_address(void* uaddr){
  //1번
  if(uaddr==NULL){
    exit(-1);
  }
  //2번
  if(!is_user_vaddr(uaddr)){
    exit(-1);
  }
 
  //3번
  void *page = pagedir_get_page(thread_current()->pagedir, uaddr);
  if (page == NULL) {
      exit(-1);  
  }
}
*/
void check_valid_string(void *str, void *esp)
{
	//str에 대한 vm_entry의 존재 여부를 확인`
	//check address를 사용
	struct vm_entry *vme = check_address(str, esp);
	if(vme == NULL)
		exit(-1);

	int size=0;//string의 사이즈를 저장하는 변수
	while(((char *)str)[size] != '\0')//string의 사이즈 측정
		size++;
	void *ptr=pg_round_down(str);
	//인자로 받은 str도 str+ size까지의 크기가 한 페이지의 크기를 넘길 수 도 있음
	for(;ptr<str+size; ptr+=PGSIZE)
	{
		//check_address를 이용해서 주소의 유저영역 여부를 검사함과 동시에 vm_entry 구조체를 얻음
		vme = check_address(ptr, esp);
		//해당 주소에 대한 vm_entry의 존재 여부와 검사
		if(vme == NULL)
			exit(-1);
	}

}

// system call에서 사용할 인자의 문자열의 주소값이 유효한 가상 주소인지 검사하는 함수로 null문자를 이용하는 것이 아닌 사이즈를 이용
void
check_valid_string_length (void *str, unsigned size, void *esp)
{
	int i;
	for(i=0; i<size; i++)
	{
		struct vm_entry *vme = check_address ((void *) (str++), esp);
		if(vme == NULL)
			exit(-1);
	}
}


//buffer가 swap되지 않도록 pin해놓는 역할
void pin_buffer (void *start, int size)
{
	void *ptr;
	for (ptr=start; ptr < start+size; ptr += PGSIZE)
	{
		struct vm_entry *vme=find_vme(ptr);
		vme->pinned = true;
		if(!vme->is_loaded)
			handle_mm_fault(vme);
	}
}
//buffer를 pin해논 것을 다시 swap할 수 있도록 unpin하는 역할
void unpin_buffer (void *start, int size)
{
	void *ptr;
	for (ptr=start; ptr < start+size; ptr += PGSIZE)
	{
		struct vm_entry *vme=find_vme(ptr);
		vme->pinned = false;
	}
}


void halt(void){
    shutdown_power_off();
}

/*
1. 현재 실행중인 쓰레드를 받아온다
2. status를 바꾼다. exit_flag를 바꾼다.
3. exit status또한 인자로 받아온 status로 바꾼다. 이게 맞는지 조금 애매
4. sema_up을 통해 부모의 wait을 풀어준다.


모든 것을 종료 후 sema_up을 통해 이놈을 이제 사용해도 된다고 알린다. (우리 코드내에서는 wait을 그만하고 이 놈을 가져가서 없애버려도 된다)

*/

void exit(int status){
  //1번
  struct thread *t=thread_current();
  //printf("%s: exit(%d)\n", thread_name(), status);
  t->exit_status=status;
  t->exit_flag = true;
  for(int i=3;i<128;i++){
    if(t->file_descriptor[i]!=NULL){
      close(i);
      t->file_descriptor[i] = NULL;
    }
  }



  struct list_elem* elem;
  struct thread* tem;
    for(elem=list_begin(&thread_current()->child_threads);elem!=list_end(&thread_current()->child_threads);elem=list_next(elem)){
    tem = list_entry(elem, struct thread, child_thread_elem);
    process_wait(tem->tid);
    
  }


  thread_exit();
}



struct thread* get_child_process(tid_t pid){
  struct thread* child_thread;
  struct list_elem* elem;
 
  for(elem=list_begin(&(thread_current()->child_threads)); elem!=list_end(&(thread_current()->child_threads)); elem=list_next(elem)){
    child_thread=list_entry(elem, struct thread, child_thread_elem);
    if(pid==child_thread->tid){
      return child_thread;
    }
  }
  return NULL;
}

/*
Runs the executable whose name is given in cmd line, passing any given arguments,
and returns the new process’s program id (pid)



*/
tid_t exec(const char* cmd_line){
  //printf("EXEC(syscall) : file name is %s\n", cmd_line);
  tid_t pid = process_execute(cmd_line);
  if(pid == TID_ERROR){
    return -1;
  }
  return pid;
}


/*
child process의 pid를 기다린다. 이건 우리가 배운 세마포어나 뮤텍스로 기다리게 하자.
retrieves the child’s exit status. 자식의 exit status를 찾아온다.

child process가 termianted된 상황에서 부모가 wait을 부르는건 가능한 상황이다.
하지만 이 상황에서도 커널은 부모가 child's exit status를 가져올 수 있도록 해야한다.
or learn that the child was terminated by the kernel 이 말이 뭔말이냐?

내가 기다리는 pid를 검색해서 끝나는것을 세마포어로 기다려야한다.

1. 자식 리스트를 순회한다.
 1-1 순회하다가 내가 찾는 tid를 발견한다. ->
 - list는 head와 끝 elem 저장
 - list_elem으로 이동
 1-2 해당 tid가 exit인지 확인한다. 
 * 여기서의 중요한 점은 exit을 했을 때 부모의 리스트에서 아예 지워버리면 내가 찾는 tid를 못찾을 수도 있다는 것이다.
 * 그래서 실제처럼 종료랑 실제 메모리랑 등등을 압수해가는 것은 나중의 일이다.?

*/



int wait(tid_t pid){

    return process_wait(pid);
}

/*
void check_valid_buffer(void *buffer, unsigned size, bool to_write) {
  char *local_buffer = (char *)buffer;
  for (unsigned i = 0; i < size; i++) {
    check_address((void *)(local_buffer + i));
  }
}
*/
/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes
actually read (0 at end of file), or -1 if the file could not be read (due to a condition
other than end of file). Fd 0 reads from the keyboard using input_getc().

이런 설명이 존재한다. 
1. fd가 열려있는지 확인한다.
2. fd에서 bytes사이즈만큼 읽어서 버퍼로 옮긴다?
3. 실제로 읽은 bytes를 return한다
 3-1 EOF인 경우 0을
 3-2 file이 EOF가 아니라 다른 이유로 안열린다면 -1
 

 이런 등등이 있는데 우리가 프로젝트 1에서 할 것은 stdin에 대해서만 한다고 한다. 그러니까 stdin(0) 즉 키보드 입력으로만 받는다 가정하고 하자.
fd0은 input_getc()를 통해 받아온다.

input_getc를 통해 char 하나를 받아오는 느낌인데 왜 자료형이 uint8_t일까?  

*/


int read(int fd, void *buffer, unsigned size){

  
  unsigned int read_size = 0;
  uint8_t *buffer_pointer = (uint8_t*) buffer;

  pin_buffer(buffer, size);

  if (fd == 0) {
    while (read_size < size) {
      *(buffer_pointer + read_size) = input_getc(); 
      read_size++; 
    }
    unpin_buffer(buffer, size);
    return read_size;
  }



  if (fd <= 0 || fd >= 128) {
        unpin_buffer(buffer, size);
    exit(-1);
  }

  struct thread* t = thread_current();
  struct file* f = t->file_descriptor[fd];
  if(f == NULL){
        unpin_buffer(buffer, size);

    exit(-1);
  }

  lock_acquire(&file_lock);
  read_size = file_read(f, buffer, size);
  lock_release(&file_lock);
	unpin_buffer(buffer, size);
  return read_size;
}


/*
project 1
Fd 1 writes to the console. Your code to write to the console should write all of buffer
in one call to putbuf(), at least as long as size is not bigger than a few hundred
bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output
by different processes may end up interleaved on the console, confusing both human
readers and our grading scripts

1. 한 번의 putbuf로 전부다 출력을 한다. (이렇게 안하면 여러 프로세스가 작동하며 우리의 콘솔에 올라와 grading scripts에 혼동이 가능)
 1-1 너무 큰 사이즈라서 나누는 경우는 일단 없다고 생각하자.

이것을 기반으로 하면 될 것 같다.
*/



int write(int fd, const void* buffer, unsigned size){
  if(size==0){
    return 0;
  }

  pin_buffer(buffer, size);

  if (fd == 1) {
    // 표준 출력 처리
    putbuf(buffer, size);
	unpin_buffer(buffer, size);

    return size;
  }

  if (fd <= 1 || fd >= 128) {
    	unpin_buffer(buffer, size);

    exit(-1);
  }

  struct thread* t = thread_current();
  struct file* f = t->file_descriptor[fd];
  int write_size = 0;
  if(f == NULL){
    	unpin_buffer(buffer, size);

    exit(-1);
  }

  lock_acquire(&file_lock);
  write_size = file_write(f, buffer, size);
  lock_release(&file_lock);
	unpin_buffer(buffer, size);

  return write_size;
}

bool create(const char *file, unsigned initial_size){
  if(file==NULL){
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  if(file==NULL){
    exit(-1);
  }
  return filesys_remove(file);
}

void close(int fd){
  if(fd<=0 || fd>=128){
    exit(-1);
  }
  struct thread* t = thread_current();
  struct file* f = t->file_descriptor[fd];

  if(f==NULL){
    exit(-1);
  }
  file_close(f);
  t->file_descriptor[fd]=NULL;
}

int filesize(int fd){
  struct thread* t = thread_current();
  struct file* f = t->file_descriptor[fd];
  if(f==NULL){
    exit(-1);
    }
  return file_length(f);
}

void seek(int fd, unsigned int position){
  struct thread* t = thread_current();
  struct file* f = t->file_descriptor[fd];
  if(f==NULL){
    exit(-1);
    }
  file_seek(f, position);
}

unsigned int tell(int fd){
  struct thread* t = thread_current();
  struct file* f = t->file_descriptor[fd];
  if(f==NULL){
    exit(-1);
    }
  return file_tell(f);
}

/*
파일을 열고 null이면 -1을 return
존재하면 file struct를 만들고 file descriptor에 넣고
그 index를 return한다.
*/


int open(const char* file_name){
  int fd= -1;
  struct thread* t = thread_current();
  if(file_name==NULL || file_name[0]=='\0'){
    return -1;
  }
  lock_acquire(&file_lock);
  
  struct file* file = filesys_open(file_name);
  if(file==NULL){
    lock_release(&file_lock);
    return -1;
  }

  for(int i=3; i<128; i++){
    if(t->file_descriptor[i]==NULL){
      t->file_descriptor[i] = file;
      fd = i;
      break;
    }
  }
  lock_release(&file_lock);
  return fd;
}


/*
lib의 syscall-nr.h를 참고해서 syscall을 swtich로 케이스에 따라 실행하자.
*/

int mmap(int fd, void *addr)
{
	int mapid;
	struct mmap_file *m_file;

	//인자들을 체크하여 Valid하지 않을 시 에러 반환
	if(process_get_file(fd)==NULL || !is_user_vaddr(addr) || pg_ofs(addr) !=0 || !addr )
		return -1;

	//addr의 공간에 이미 다른 vm_entry가 있다면 이는 올릴 수 없음
	if(find_vme(addr))
		return -1;

	//file_reopen
	struct file *reopened_file = file_reopen(process_get_file(fd));

	//mapid 할당
	mapid=thread_current()->next_mapid++;

	//mmap_file 생성 및 초기화
	m_file=malloc(sizeof(struct mmap_file));
	if(m_file==NULL)
		return -1;
	m_file->mapid = mapid;
	m_file->file = reopened_file;
	list_push_back(&(thread_current()->mmap_list), &(m_file->elem));  //mmap_file들의 리스트 연결을 위한 구조체
	list_init(&(m_file->vme_list));

	//vm_entry 생성 및 초기화
	int read_bytes = file_length(m_file->file);//읽어야할 바이트의 수
	int ofs=0;
	while (read_bytes > 0)
	{

		/* Calculate how to fill this page.
		   We will read PAGE_READ_BYTES bytes from FILE
		   and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		//vm entry 생성(malloc 사용)
		struct vm_entry *vme = malloc(sizeof(struct vm_entry));
		//vm_entry 멤버들 설정, 가상페이지가 요구될 때 읽어야할 파일의 오프셋과 사이즈, 마지막에 패딩할 제로바이트 등등
		vme->type = VM_FILE;
		vme->vaddr = addr;
		vme->writable = true;
		vme->is_loaded = false;
		vme->file = m_file->file;
		vme->offset = ofs;
		vme->read_bytes =page_read_bytes;
		vme->zero_bytes =page_zero_bytes;
		list_push_back(&(m_file->vme_list), &vme->mmap_elem);
		//insert_vme()함수를 사용해서 생성한 vm_entry를 해시 테이블에 추가
		insert_vme(&thread_current()->vm, vme);

		/* Advance. */
		read_bytes -= page_read_bytes;
		//옵셋에 대한 정보도 담아야하므로 옵셋 정보 갱신 필요
		ofs += page_read_bytes;
		addr += PGSIZE;
	}

	//return map_id
	return mapid;
}

//mmap_list내에서 mapping에 해당하는 mapid를 갖는 모든 vmentry를 해제
void munmap(int mapid)
{

	struct thread * cur= thread_current();

		struct mmap_file *m_file=NULL;
		//mmap_list 순회
		struct list_elem *e;
		for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); e = list_next(e)) {
			struct mmap_file *check_mmap_file = list_entry(e, struct mmap_file, elem);
			//mapid에 해당하는 mmap file을 찾은 경우
			if (check_mmap_file->mapid == mapid) {
				m_file = check_mmap_file;
				break;
			}
		}
		//mapid에 해당하는 mmap_file을 못찾은 경우
		if (m_file == NULL)
			return;

		//vm_entry 제거
		//페이지 테이블 entry 제거
		//mmap_file 제거
		//file_close
		do_munmap(m_file);
}




static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void* esp = f->esp;
  check_address(esp, f->esp);
  switch(*(uint32_t*)(f->esp)){
    case SYS_HALT:
    halt();
    break;     
 
    case SYS_EXIT:
    exit(*(int*)(f->esp+4));
    break;
 
    case SYS_EXEC:
    check_valid_string((char*)*(uint32_t*)(f->esp+4), f->esp);    
    f->eax=exec((char*)*(uint32_t*)(f->esp+4));
    break;

    case SYS_WAIT:
    f->eax = wait(*(uint32_t*)(f->esp+4));
    break;

    case SYS_CREATE:    
    check_valid_string((char*)*(uint32_t*)(f->esp+4), f->esp);
    f->eax = create((char*)*(uint32_t*)(f->esp+4), *(uint32_t*)(f->esp+8));
    break;

    case SYS_REMOVE:              
    check_valid_string((char*)*(uint32_t*)(f->esp+4), f->esp);    
    f->eax = remove((char*)*(uint32_t*)(f->esp+4));
    break;

    case SYS_OPEN:                  
    check_valid_string((char*)*(uint32_t*)(f->esp+4), f->esp);
    f->eax = open((char*)*(uint32_t*)(f->esp+4));
    break;

    case SYS_FILESIZE:               
    f->eax = filesize(*(uint32_t*)(f->esp+4));
    break;

    case SYS_READ:
    check_valid_string_length((void*)*(uint32_t*)(f->esp+8), (unsigned)*(uint32_t*)(f->esp+12), f->esp);
    f->eax = read((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
    break;

    case SYS_WRITE:
    check_valid_string_length((void*)*(uint32_t*)(f->esp+8), (unsigned)*(uint32_t*)(f->esp+12), f->esp);
    f->eax = write((int)(*(uint32_t *)(f->esp+4)),  (void*)(*(uint32_t *)(f->esp+8)), (unsigned)(*(uint32_t *)(f->esp+12)));
    break;

    case SYS_SEEK:                 

    seek((int)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
    break;

    case SYS_TELL:                  
    f->eax = tell((int)*(uint32_t*)(f->esp+4));
    break;

    case SYS_CLOSE:                 
    close(*(uint32_t*)(f->esp+4));
    break;

		case SYS_MMAP:
			f->eax = mmap((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8));
			break;

		case SYS_MUNMAP:
			munmap((int)*(uint32_t*)(f->esp+4));
			break;
  }
  //printf ("system call! %d\n", *(int32_t*)(f->esp));
}
