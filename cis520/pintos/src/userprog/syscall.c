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
//added
void* check_addr (const void*);
struct proc_file* list_search (struct list *, int);

//added struct to represent a process file
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
// includes a switch statement with all possible cases which call the relevant functions accordingly. 
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
/*
Calls the shutdown_power_off function 
*/
void 
sys_halt (void) 
{
    shutdown_power_off ();
}


/*
Iterates over the siblings list of current thread, creates a child for each list entry, checks this child's tid against the current thread's. If matched, it sets the used field of the child to true and its exit_errror to the int that was passed into the method.
 If the loop was exited without finding a match, it sets the current thread's error_code to the status. 
 Finally, if the current thread's parent is still waiting on it, the semaphore is incremented 

*/
void 
sys_exit (int status)
{
	struct list_elem *e;
	
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

	if(thread_current()->parent->tid_waiting_on == thread_current()->tid)
		sema_up (&thread_current ()->parent->child_lock);
	thread_exit ();
}

/*
Acquires the lock on the filesystem, uses amlloc to allocate memory for a char pointer. It then copies the filename into memory using the strlcpy function. Then it uses strtok_r to tokenize the filename and store it in fn_cp which is passed into filesys_open and stores the resulting file in a new struct. If this new strcut variable still holds a null value, the lock on the filesystem is released, and a -1 is returned. If the value id non-null, the file is closed, the lock is released and the process_execute function from process.c is called. The result it produced is returned.   
*/
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


/*
calls the process_wait function in process.c
*/
int 
sys_wait (pid_t pid)
{
    return process_wait (pid);
}

/*
calls filesys_create in filesys.c
*/
bool 
sys_create (const char *file_name, unsigned initial_size)
{
    return filesys_create (file_name, initial_size);
}

/*
calls filesys_remove in filesys.c
*/
bool 
sys_remove (const char *file_name)
{
    return filesys_remove (file_name) != NULL;
}

/*
First checks if the file passed in is a null value, if so, returns a -1. Otherwise, allocates memory for a process file, assigns the filename (that was passed in as the argument to the function) to the ptr field of the struct. The fd_count field of the current thread is incremented by 1 as one more process is now using this file. This file must be added to the all_files list of the current thread.
*/
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


/*returns the length of the file as an int*/
int 
sys_filesize (struct file *file)
{
    return file_length (file);
}


/*
function to read the file. A pointer to the file is passed in as an argument. Checks if the spot next to this pointer in memory is free. If it is, declares a pointer called buffer at a location 2 spots below the one passed in. It then uses a loop to read the file by calling the input_getc function and stores it in the buffer. If the spot is not empty, the list_search function in list.c is called to look for the file in the list of all_files of the current thread. If it wasn't found, returned -1. Otherwise, the file was found and it must be read by first acquiring the lock to the filesystem, then calling file_read, releasing the lock and returning the results of file_read.  
*/
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
  	struct proc_file *file_ptr = list_search (&thread_current()->all_files, *(ptr+1));
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

/*

*/
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

/*calls file_seek in filesys.c*/
void 
sys_seek (int fd, unsigned position)
{
	return file_seek (fd, position);
}

/*calls file_tell in filesys.c*/
unsigned 
sys_tell (int fd)
{
  return file_tell (fd);
}


/*
Function to close the file. First checks the all_files list, if that is empty, there are no files to close so we return out of the function. If it isn't empty, we look for the given file in that list and store a pointer to it. Then we call file_close which closes the file, remove this file from its list and frees the memory that was allocated for the file. 
*/
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


/*
Function to close all files in the list which is provided as an argument. Loops over the list, pops each entry and stores it in a temporary variable, them creates a process file using this variable. It then calls file_close and passes in a pointer to this file after which it is removed from the list. Finally, the memory allocated for each file is freed.
*/
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
/*
Looks for a given file in a given list. Iterates over the list , creates a file for each element of the list, checks its file descriptor against the one provided as a parameter. If they match, the file is returned. If no such file exists, returns null
*/
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

/*
calls is_user_vaddr which returns true if VADDR is a user virtual address. If it is not, calls sys_exit with -1 and returns 0. If it returns true, we call pagedir_get_page and store the results in a pointer. If this pointer holds a non-null value, it is returned. Otherwise, the same process is repeated where sys_exit was called and 0 was returned. 
*/
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
