#include "obj/u-asm.h"

.text
.globl _Z9sys_clonePFiPvES_Pc
_Z9sys_clonePFiPvES_Pc:
  subq $16, %rdx
  movq %rsi, 8(%rdx)
  movq %rdi, 0(%rdx)

  movq $23, %rax
  movq %rdx, %rdi

  syscall

  testq %rax, %rax
  jz child_thread

parent_thread:
  retq

child_thread:
  popq %rax
  popq %rdi
  call *%rax

  movq %rax, %rdi
  movq $24, %rax
  syscall
