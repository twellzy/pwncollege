.intel_syntax noprefix
.global _start

.data
	response:
		.asciz "HTTP/1.0 200 OK\r\n\r\n"

	buffer: .space 4096
	readbuffer: .space 4096
	writebuffer: .space 1024
	path: .space 256


.section .text
_start:
	mov rax, 0x29
	mov rdi, 0x2
	mov rdx, 0x0
	mov rsi, 0x1
	syscall		#socket
	
	push r12
	mov word ptr [rsp], 0x02
	mov word ptr [rsp+3], 0x50
	mov rdi, 0x3
	mov rsi, rsp
	mov rdx, 16
	mov rax, 49
	syscall		#bind
	
	mov rdi, 0x3
	xor rsi, rsi
	mov rax, 50
	syscall		#listen
	
	mov rax, 43
	mov rdi, 0x3
	xor rsi, rsi
	xor rdx, rdx
	xor r10, r10
	syscall		#accept
	
	fork:
		mov rax, 57	#fork
		syscall
		
		cmp rax, 0	#childchecker
		jz action

		mov rax, 0x3
		mov rdi, 0x4
		syscall	#close
	
		mov rax, 43
		mov rdi, 3
		xor rsi, rsi
		xor rdx, rdx
		syscall	#accept
		inc r10
		cmp r10, 0x150
		jb fork
		
	exit:
		mov rdi, 0
		mov rax, 0x3c
		syscall	#exit
	
	
parser:	
				#rdi = buffer   #rsi = path
	xor rcx, rcx
	add rcx, 4
	add rcx, rdx
	mov r8, rcx
	xor r9, r9
	while:
		mov rdx, rdi
		add rdx, rcx
		mov bl, byte ptr [rdx]
		cmp bl, 0x20
		je return
		sub rcx, r8
		lea r11, [path+rcx]
		add rcx, r8
		mov byte ptr [r11], bl
		inc rcx
		jmp while
	return:
		ret
		
		
parser2:
	xor rcx, rcx
	xor rdx, rdx
	xor r8, r8
	xor r9, r9
	loop:
		inc rcx
		inc r8
		lea rax, [buffer+rcx]
		mov bl, byte ptr [rax]
		cmp bl, 0x00
		jne loop
	
	sub rcx, 1
	loop2:
		lea rax, [buffer+rcx]
		mov bl, byte ptr [rax]
		cmp bl, 0x0a
		je magic
		sub rcx, 1
		inc rdx
		jmp loop2
		
	magic:
		sub rdx, 1
		sub r8, rdx
		sub r8, 1
		
	loop3:
		lea rax, [buffer+r8]
		mov bl, byte ptr [rax]
		mov byte ptr [writebuffer+r9], bl
		cmp r9, rdx
		ja return2
		inc r9
		inc r8
		jmp loop3
		
		
	return2:
		mov rax, r9
		ret
		
		
		

		

		
action:
	mov rax, 3
	mov rdi, 3
	syscall		#close
	
	pop r12
	xor rax, rax
	mov rdi, 0x4
	lea rsi, [buffer]
	mov rdx, 1024
	syscall
	mov r12, rax		#read
	
	lea rsi, [buffer]
	mov bl, byte ptr [rsi]
	cmp bl, 0x50
	je post
	jmp get
	
get:
	lea rdi, [buffer]
	lea rsi, [path]
	mov rdx, 0
	call parser		#file path parser

	mov rax, 2
	lea rdi, [path]
	xor rsi, rsi		#CHANGE
	syscall		#open

	xor rax, rax
	mov rdi, 3
	lea rsi, [readbuffer]
	mov rdx, 500
	syscall		#read
	mov r9, rax

	mov rax, 0x3		#close
	mov rdi, 3
	syscall

	mov rax, 1
	mov rdi, 4
	lea rsi, [response]
	mov rdx, 19
	syscall		#write
	
	mov rax, 1
	mov rdi, 4
	lea rsi, [readbuffer]
	mov rdx, r9
	syscall		#write
	jmp exit
	
post:
	lea rdi, [buffer]
	lea rsi, [path]
	mov rdx, 1
	call parser		#file path parser
	mov r9, rax
	
	mov rax, 2
	lea rdi, [path]
	mov rsi, 0x41
	mov rdx, 0777
	syscall		#open
	

	call parser2
	mov r12, rax
	
	
	mov rax, 1
	mov rdi, 3
	lea rsi, [writebuffer]
	mov rdx, r12
	syscall		#write
	
	mov rax, 3
	mov rdi, 3
	syscall		#close
	
	mov rax, 1
	mov rdi, 4
	lea rsi, [response]
	mov rdx, 19
	syscall		#write
	
	jmp exit
	
	
	
	
