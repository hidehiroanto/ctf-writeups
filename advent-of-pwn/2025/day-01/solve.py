#!/usr/bin/env python3

from pwn import *

context.binary = '/challenge/check-list'
code = disasm(context.binary.section('.text'))
instructions = re.findall(r'(add|cmp|sub) +BYTE PTR \[rbp(-0x[0-9a-f]+)\], (0x[0-9a-f]+)', code)
buffer = 0x400 * [0]

for i in instructions:
    buffer[int(i[1], 0)] += int(i[2], 0) * (-1 if i[0] == 'add' else 1)

password = bytes(b & 0xff for b in buffer)
info(f'Password (hex): {password.hex()}')

with process() as p:
    p.sendline(password)
    success(f'Flag: {p.recvall().split()[-1].decode()}')
