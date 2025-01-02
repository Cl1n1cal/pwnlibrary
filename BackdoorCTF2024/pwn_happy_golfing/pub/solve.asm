section .data
	;hello_msg db "AAAAAAAAAAAAAAmj", 0
	binsh db "/bin/sh",0

section .text
	global _start
_start:
	jg 0x47
	dec esp
	inc esi
	mov eax, 0x0b
	mov ebx, binsh
	xor ecx, ecx
	xor edx, edx
	int 0x80
	

