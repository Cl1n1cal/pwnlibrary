#include <stdio.h>
//gcc -fno-stack-protector -no-pie sigrop.c -o sigrop

int sigrop()
{
    char *hello = "/bin/sh\0";
        asm(
		"popq %rax;"
		"ret;"
		"syscall;" //Don't need ret after syscall, but both works
	   );
    return 0;
}

int main()
{
	char buffer[32];
	puts("Buffer ready:");
	fgets(buffer, 250, stdin);
	return 0;
}
