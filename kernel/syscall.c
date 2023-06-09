/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "elf.h"
#include "process.h"
#include "util/functions.h"

#include "spike_interface/spike_utils.h"

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
  sprint(buf);
  return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
  sprint("User exit with code:%d.\n", code);
  // in lab1, PKE considers only one app (one process). 
  // therefore, shutdown the system when the app calls exit()
  shutdown(code);
}

ssize_t sys_print_backtrace(uint64 level)
{
  //sprint("now sys_print_backtrace level:%d\n", level);
  int func_num;
  function_name func_name[256];
  load_function_name(current, &func_num, func_name);
  //sprint("%p\n", func_num);
  //for(int i=0;i<func_num;i++) sprint("%s %p\n",func_name[i].name, func_name[i].addr);

  uint64 fp=*((uint64*)current->trapframe->regs.s0-1);
  for(int i=0;i<level;i++)
  {
    uint64 ra=*((uint64*)fp-1);
    if(!ra) break;

    char *name="?";
    uint64 tmp=-1;
    for(int j=0;j<func_num;j++)
    {
      if(func_name[j].addr<ra&&ra-func_name[j].addr<tmp)
      {
        tmp=ra-func_name[j].addr;
        name=func_name[j].name;
      }
    }
    sprint("%s\n", name);

    fp=*((uint64*)fp-2);
  }
  return 0;
}

//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
  switch (a0) {
    case SYS_user_print:
      return sys_user_print((const char*)a1, a2);
    case SYS_user_exit:
      return sys_user_exit(a1);
    case SYS_user_print_backtrace:
      return sys_print_backtrace(a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
