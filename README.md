# CTFs
Here I will try to upload all challenges in any CTF i join.

### kernel-ret2usr

This challenge is a simple one for Kernel exploits without the following mitigates
| Name | Description |
|------|-------------|
| Kernel address space layout randomization (KASLR) | it randomizes the base address where the kernel is loaded each time the system is booted |
| Supervisor mode execution protection (SMEP) | marks all the userland pages in the page table as non-executable when the process is in kernel-mode. In the kernel, this is enabled by setting the 20th bit of Control Register CR4.  |
| Supervisor Mode Access Prevention (SMAP) | marks all the userland pages in the page table as non-accessible when the process is in kernel-mode, which means they cannot be read or written as well. In the kernel, this is enabled by setting the 21st bit of Control Register CR4. |
| Kernel page-table isolation (KPTI) | kernel separates user-space and kernel-space page tables entirely, instead of using just one set of page tables that contains both user-space and kernel-space addresses. |

Note that the real challenge belongs to hexCTF2020 with the name kernel-rop but for learning i modified it and removed mitigates
