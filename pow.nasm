BITS 64
pow:
cmp rsi, 1
jl check
loop:
add rdx, rdx
dec rsi
jnz loop
check:
cmp rdx, rax
je clear
ret
clear:
nop