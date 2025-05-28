#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/*------[ Project 2 System Call]------*/
// #include "threads/init.h"
#include "user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h" 

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/*------------------[Project2 - System Call]------------------*/ 
void syscall_half(void);
void syscall_exit(int status);
int syscall_exec(const char *cmd_line);
bool syscall_create(const char *file, unsigned initial_size);
int syscall_wait(pid_t pid);
pid_t syscall_fork(const char *thread_name, struct intr_frame *if_ UNUSED);
int syscall_write(int fd, const void *buffer, unsigned size);
bool syscall_remove(const char *file);
int syscall_open(const char *file);
int syscall_filesize(int fd);
int syscall_read(int fd, void *buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);
void check_addr(const void *addr);
struct file *fd_tofile(int fd);
/*------------------[Project2 - System Call]------------------*/

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* pintOS 종료 */
void syscall_half(void)
{
	power_off();
}

/* 현재 실행중인 유저 프로세스 종료
 * 유저 프로세스 종료 상태 - status
 * status == 0 - 성공
 * status != 0 - error
 */
void syscall_exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

/* 파일 생성
 * 파일명 - file
 * 크기 - initial_size
 * return - 성공 or 실패
*/
bool syscall_create(const char *file, unsigned initial_size)
{
	check_addr(file);

	lock_acquire(&filesys_lock);
	bool cre = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return cre;
}

/* 자식 프로세스 대기
 * 자식 프로세스가 모두 종료 시 exit_status 리턴
 * 자식 프로세스 아이디 - pid
*/
int syscall_wait(pid_t pid)
{
	return process_wait(pid);
}

/* 프로세스 복제
 * 복제될 프로세스 이름 - thread_name
 * 부모 프로세스 프레임 - if_ (부모 프레임을 자식 프로세스에게 전달하기 위한 매개변수)
 * return - 자식 프로세스 pid (리소스 복제 실패시 tid_error 반환)
 */
pid_t syscall_fork(const char *thread_name, struct intr_frame *if_ UNUSED)
{
	return process_fork(thread_name, if_);
}

/* 파일 디스크립터 FD에 연결된 파일이나 장치에 BUFFER로부터 SIZE 바이트만큼 데이터를 씁니다.
 *
 * 매개변수:
 * - fd: 파일 디스크립터 (예: 표준 출력은 1)
 * - buffer: 사용자 영역에서 데이터를 읽어올 버퍼의 주소
 * - size: 출력할 바이트 수
 *
 * 반환값:
 * - 실제로 기록한 바이트 수를 반환합니다.
 * - 유효하지 않은 fd이거나 기록에 실패하면 -1을 반환합니다.
 */
int syscall_write(int fd, const void *buffer, unsigned size)
{
	check_addr(buffer);
	check_addr(buffer + size - 1);

	 if (size == 0)
        return 0;
		
	// console에 쓴다.(표준 출력)
	if (fd == 1)
	{
		lock_acquire(&filesys_lock);
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}
	else if (fd == 0)
	{
		// syscall_exit(-1);
		return -1;
	}
	else if (fd > 1 && fd < 64)
	{
		struct file *write_file = fd_tofile(fd);
		if (write_file == NULL)
		{
			syscall_exit(-1);
		}
		else
		{
			lock_acquire(&filesys_lock);
			int wri = file_write(write_file, buffer, size);
			lock_release(&filesys_lock);
			return wri;
		}
	}
	syscall_exit(-1);
}

/* cmd_line을 읽어서 프로세스 실행
 * 
 * 프로세스 로드 실패 - exit_status = -1
 * 실패시 프로세스 종료 
*/
int syscall_exec(const char* cmd_line){
	check_addr(cmd_line);
	if(process_exec(cmd_line)<0){
		syscall_exit(-1);
	}
	return thread_current()->tid;
}
 

/** 이름이 file인 파일 삭제
 * 삭제 성공 - true
 * 삭제 실패 - false
*/
bool syscall_remove(const char *file)
{
	check_addr(file);
	lock_acquire(&filesys_lock);
	bool rem = filesys_remove(file);
	lock_release(&filesys_lock);
	return rem;
}

/** 이름이 file인 파일 열기
 * 성공시 - fd 반환
 * 실패시 - -1 반환
*/
int syscall_open(const char *file)
{
	check_addr(file);
	struct thread *curr = thread_current();

	int open_fd;
	bool is_not_full = false;
	for (open_fd = 2; open_fd < 64; open_fd++)
	{
		if (curr->fd_table[open_fd] == NULL)
		{
			is_not_full = true;
			break;
		}
	}
	if (!is_not_full)
		return -1;

	lock_acquire(&filesys_lock);
	struct file *open_file = filesys_open(file);
	lock_release(&filesys_lock);
	if (open_file == NULL){
		file_close(open_file);
		return -1;
	}

	curr->fd_table[open_fd] = open_file;
	curr->fd = open_fd;

	return open_fd;
}

/*** 파일 크기 리턴 함수
 * 성공 시 - fd 파일 사이즈 바이트 단위 반환
 * 실패 시 - syscall_exit(-1)
*/
int syscall_filesize(int fd)
{
	lock_acquire(&filesys_lock);
	struct file *size_file = fd_tofile(fd);
	lock_release(&filesys_lock);

	if (size_file == NULL)
	{
		syscall_exit(-1);
	}

	return file_length(size_file);
}

/* 파일 디스크립터 fd로부터 size 바이트만큼 데이터를 읽어 buffer에 저장합니다.
 *
 * 매개변수:
 * - fd: 읽기 대상 파일의 파일 디스크립터 (예: 0은 표준 입력)
 * - buffer: 읽은 데이터를 저장할 사용자 메모리 주소
 * - size: 읽을 바이트 수
 *
 * 반환값:
 * - 실제로 읽은 바이트 수를 반환
 * - 읽기에 실패하거나 fd가 유효하지 않으면 -1 또는 0을 반환
 *
 */
int syscall_read(int fd, void *buffer, unsigned size)
{
	check_addr(buffer);
	check_addr(buffer + size - 1);

	if (size == 0)
	{
		return 0;
	}

	if (fd == 0)
	{
		char *buf = (char *)buffer;
		lock_acquire(&filesys_lock);
		for (int i = 0; i < size; i++)
		{
			buf[i] = input_getc();
		}
		lock_release(&filesys_lock);
		return size;
	}
	else if (fd == 1)
	{
		return -1;
	}
	else if (fd > 1 && fd < 64)
	{

		struct file *read_file = fd_tofile(fd);
		if (read_file == NULL)
		{
			return 0;
		}
		else
		{
			lock_acquire(&filesys_lock);
			int rea = file_read(read_file, buffer, size);
			lock_release(&filesys_lock);
			return rea;
		}
	}
	syscall_exit(-1);
}

/* 열린 파일의 읽기/쓰기 위치를 지정한 위치(position)로 이동시킵니다.
 *
 * 매개변수:
 * - fd: 이동할 대상 파일의 파일 디스크립터 (2 이상)
 * - position: 새로 설정할 오프셋 (파일의 앞에서부터 position 바이트 떨어진 위치)
 */
void syscall_seek(int fd, unsigned position)
{
	if (fd < 2)
	{
		return;
	}

	struct file *seek_file = fd_tofile(fd);

	if (seek_file == NULL)
	{
		return;
	}
	lock_acquire(&filesys_lock);
	file_seek(seek_file, position);
	lock_release(&filesys_lock);
}

/** 열린 파일의 현재 읽기/쓰기 위치(position)를 반환
 * fd - 위치 확인할 fd
 * 반환 - 파일 내 현재 읽기/쓰기 위치 (실패 시 0 반환)
*/
unsigned syscall_tell(int fd)
{
	if (fd < 2)
	{
		return 0;
	}

	if (fd < 0 || 64 <= fd)
	{
		return 0;
	}

	struct file *tell_file = fd_tofile(fd);

	if (tell_file == NULL)
	{
		return 0;
	}
	lock_acquire(&filesys_lock);
	unsigned tell = file_tell(tell_file);
	lock_release(&filesys_lock);

	return tell;
}

/** fd에 해당하는 파일 닫기
 * fd - 닫을 파일의 fd
*/
void syscall_close(int fd)
{
	struct thread *curr = thread_current();

	if (fd < 2)
	{
		return;
	}

	struct file *cl_file = fd_tofile(fd);

	if (cl_file == NULL)
	{
		syscall_exit(-1);
	}

	if (fd < 0 || 64 <= fd)
	{
		return;
	}

	lock_acquire(&filesys_lock);
	file_close(cl_file);
	lock_release(&filesys_lock);
	curr->fd_table[fd] = NULL;
}

/* 사용자 프로그램으로부터 들어온 시스템콜을 처리 */
void
syscall_handler (struct intr_frame *f UNUSED) {
	uint64_t sys_number = f->R.rax;

	switch (sys_number)
	{
	case SYS_HALT:
		syscall_half();
		break;
	case SYS_EXIT: 
		syscall_exit(f->R.rdi);
	break;
	case SYS_FORK:
		f->R.rax = syscall_fork((const char *)f->R.rdi, f);
		break;
	case SYS_EXEC: 
		f->R.rax = syscall_exec((const char*) f->R.rdi);
		break;
	case SYS_WAIT: 
		f->R.rax = syscall_wait((pid_t)f->R.rdi);
		break;
	case SYS_CREATE: 
		f->R.rax = syscall_create((const char *)f->R.rdi, (unsigned) f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = syscall_remove((const char *)f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = syscall_open((const char *)f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = syscall_filesize((int)f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = syscall_read((int)f->R.rdi, (void *)f->R.rsi, (unsigned)f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = syscall_write((int)f->R.rdi, (const void *)f->R.rsi, (unsigned)f->R.rdx);
		break;
	case SYS_SEEK:
		syscall_seek((int)f->R.rdi, (unsigned)f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = syscall_tell((int)f->R.rdi);
		break;
	case SYS_CLOSE:
		syscall_close((int)f->R.rdi);
		break;
	case SYS_MMAP:
		break;
	case SYS_MUNMAP:
		break;
	case SYS_CHDIR:
		break;
	case SYS_MKDIR:
		break;
	case SYS_READDIR:
		break;
	case SYS_ISDIR:
		break;
	case SYS_INUMBER:
		break;
	case SYS_SYMLINK:
		break;
	case SYS_DUP2:
		break;
	case SYS_MOUNT:
		break;
	case SYS_UMOUNT:
		break;
	default:
		thread_exit();
		break;
	}
}

/** ### 주소 유효성 검사
 * ---
 * - pointer가 NULL인지 확인
 * - 사용자 영역의 가상주소인지 확인
 * - 페이지 테이블에 매핑되어 있는지 확인
*/
void check_addr(const void *addr)
{
	if (addr == NULL)
		syscall_exit(-1);
	if (!is_user_vaddr(addr))
		syscall_exit(-1);
	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		syscall_exit(-1);
}

/** fd에 매핑된 파일 반환
 * 
*/
struct file *fd_tofile(int fd)
{
	if (fd < 0 || 64 <= fd)
	{
		return NULL;
	}

	struct thread *curr = thread_current();
	struct file *file = curr->fd_table[fd];
	return file;
}