#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "list.h"
#include "process.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
void* check_addr (const void*);
struct proc_file* list_search (struct list *, int);

struct proc_file
{
	struct file *ptr;
	int fd;
	struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	int *ptr = f->esp;
	check_addr (ptr);
	
	int sys_call = *ptr;
  switch (sys_call)
  {
	  case SYS_HALT:
			sys_halt ();
		break;
		
	  case SYS_EXIT:
			check_addr (ptr+1);
			sys_exit (*(ptr+1));
		break;
	  
	  case SYS_EXEC:
			check_addr (ptr+1);
			check_addr (*(ptr+1));
			f->eax = sys_exec (*(ptr+1));
		break;
		
		case SYS_WAIT:
			check_addr (ptr+1);
			f->eax = sys_wait (*(ptr+1));
		break;
		
		case SYS_CREATE:
			check_addr (ptr+2);
			check_addr (*(ptr+1));
			acquire_filesys_lock ();
			f->eax = filesys_create (*(ptr+1), *(ptr+2));
			release_filesys_lock ();
		break;
		
		case SYS_REMOVE:
			check_addr (ptr+1);
			check_addr (*(ptr+1));
			acquire_filesys_lock ();
			f->eax = sys_remove (*(ptr+1));
			release_filesys_lock ();
		break;
		
		case SYS_OPEN:
			check_addr (ptr+1);
			check_addr (*(ptr+1));
			acquire_filesys_lock ();
			struct file *file_ptr = filesys_open (*(ptr+1));
			release_filesys_lock ();
			f->eax = sys_open (file_ptr);
		break;
		
		case SYS_FILESIZE:
			check_addr (ptr+1);
			acquire_filesys_lock ();
			f->eax = sys_filesize (list_search (&thread_current ()->all_files, *(ptr+1))->ptr);
			release_filesys_lock ();
		break;
		
		case SYS_READ:
			check_addr (ptr+3);
			check_addr (*(ptr+2));
			f->eax = sys_read (ptr);
		break;
		
		case SYS_WRITE:
			check_addr (ptr+3);
			check_addr (*(ptr+2));
			f->eax = sys_write (ptr);
		break;
		
		case SYS_SEEK:
			check_addr (ptr+2);
			acquire_filesys_lock ();
			sys_seek (list_search (&thread_current ()->all_files, *(ptr+1))->ptr, *(ptr+2));
			release_filesys_lock ();
		break;
		
		case SYS_TELL:
			check_addr (ptr+1);
			acquire_filesys_lock ();
			f->eax = sys_tell (list_search (&thread_current ()->all_files, *(ptr+1))->ptr);
			release_filesys_lock ();
		break;
		
		case SYS_CLOSE:
			check_addr (ptr+1);
			acquire_filesys_lock ();
			sys_close (&thread_current ()->all_files, *(ptr+1));
			release_filesys_lock ();
		break;
		
	  default:
	  	sys_exit(-1);
		break;
  }
}

void 
sys_halt (void) 
{
    shutdown_power_off ();
}

void 
sys_exit (int status)
{
	struct list_elem *e;
	
	//my eyes
	for (e = list_begin (&thread_current ()->parent->children); 
			 e != list_end (&thread_current ()->parent->children);
		   e = list_next (e))
	{
		struct child *c = list_entry (e, struct child, elem);
		if(c->tid == thread_current ()->tid)
		{
		  c->used = true;
			c->exit_error = status;
		}
	}	
        
	thread_current ()->exit_error = status;

	if(thread_current ()->parent->tid_waiting_on == thread_current ()->tid)
		sema_up (&thread_current ()->parent->child_lock);
	thread_exit ();
}

pid_t 
sys_exec(const char *file_name)
{
	acquire_filesys_lock ();
	char *fn_cp = malloc (strlen (file_name) + 1);
	strlcpy(fn_cp, file_name, strlen (file_name) + 1);
	
	char *save_ptr;
	fn_cp = strtok_r (fn_cp, " ", &save_ptr);

  struct file* f = filesys_open (fn_cp);

	if (f == NULL)
	{
		release_filesys_lock ();
	  return -1;
	}
	else
	{
	  file_close (f);
	  release_filesys_lock ();
	  return process_execute (file_name);
	}
}

int 
sys_wait (pid_t pid)
{
    return process_wait (pid);
}

bool 
sys_create (const char *file_name, unsigned initial_size)
{
    return filesys_create (file_name, initial_size);
}

bool 
sys_remove (const char *file_name)
{
    return filesys_remove (file_name) != NULL;
}

int 
sys_open (struct file *file_ptr)
{
    if (file_ptr == NULL)
    	return -1;
    else
    {
    	struct proc_file *proc_file = malloc (sizeof (*proc_file));
    	proc_file->ptr = file_ptr;
    	proc_file->fd = thread_current ()->fd_count;
    	thread_current ()->fd_count++;
    	list_push_back (&thread_current ()->all_files, &proc_file->elem);
    	return proc_file->fd;
    }
}

int 
sys_filesize (struct file *file)
{
    return file_length (file);
}

int 
sys_read (int *ptr)
{
	int i;
  if (*(ptr+1) == 0)
  {
  	uint8_t *buffer = *(ptr+2);
  	for (i = 0; i < *(ptr+3); i++)
  		buffer[i] = input_getc ();
  	return *(ptr+3);
  }
  else
  {
  	struct proc_file *file_ptr = list_search (&thread_current ()->all_files, *(ptr+1));
  	if (file_ptr == NULL)
  		return -1;
  	else
  	{
  		int offset;
  		acquire_filesys_lock ();
  		offset = file_read (file_ptr->ptr, *(ptr+2), *(ptr+3));
  		release_filesys_lock ();
  		return offset;
  	}
  }
}

int 
sys_write (int *ptr)
{
	if (*(ptr+1) == 1)
	{
		putbuf (*(ptr+2), *(ptr+3));
		return *(ptr+3);
	}
	else
	{
		struct proc_file *file_ptr = list_search (&thread_current ()->all_files, *(ptr+1));
		if (file_ptr == NULL)
			return -1;
		else
		{
			int offset;
			acquire_filesys_lock ();
			offset = file_write (file_ptr->ptr, *(ptr+2), *(ptr+3));
			release_filesys_lock ();
			return offset;
		}
	}
}

void 
sys_seek (int fd, unsigned position)
{
	return file_seek (fd, position);
}

unsigned 
sys_tell (int fd)
{
  return file_tell (fd);
}

void 
sys_close (struct list *all_files, int fd)
{
	if (list_empty (&all_files)) return;
	struct proc_file *f;
        f = list_search(all_files, fd);
  if(f != NULL)
  {
	file_close (f->ptr);
	list_remove (&f->elem);
	free (f);
  }
}

void 
close_all_files (struct list *files)
{
	struct list_elem *e;

	while (!list_empty (files))
	{
    	e = list_pop_front(files);
		  struct proc_file *f = list_entry (e, struct proc_file, elem);
	    file_close (f->ptr);
	    list_remove (e);
	    free (f);
	}
}

struct proc_file* 
list_search (struct list *files, int fd)
{
    struct list_elem *e;
    for (e = list_begin (files); 
         e != list_end (files);
         e = list_next (e))

    {
      struct proc_file *f = list_entry (e, struct proc_file, elem);
	    if (f->fd == fd)
	    	return f;
    }

   return NULL;
}

void* 
check_addr (const void *vaddr)
{
	if (!is_user_vaddr (vaddr))
	{
		sys_exit (-1);
		return 0;
	}
	void *ptr = pagedir_get_page (thread_current ()->pagedir, vaddr);
	if (!ptr)
	{
		sys_exit (-1);
		return 0;
	}
	return ptr;
}
