#!/usr/bin/env python3

from pwn import *

flag_length = os.path.getsize('/flag')

get_pyc = '''
from importlib.util import MAGIC_NUMBER
from marshal import dumps
from struct import pack
from sys import stdout

code = dumps(compile('import gifts; print(gifts.flag)', '', 'exec'))
stdout.buffer.write(MAGIC_NUMBER + pack('<I', 3) + pack('<Q', 0xf0a0101a75bc9dd3) + code)
'''

pyc = process(['python3.13', '-c', get_pyc]).recvall()
with process('/challenge/run.sh') as p:
    send = lambda data: p.sendlineafter(b'~ # ', data)
    send(b'stty -echo')
    send(b'head -n 1 $(dirname $(grep -l 0x1337 /sys/bus/pci/devices/*/vendor))/resource | cut -d" " -f1')
    pypu_base = int(p.recvline(), 0)

    send(b'devmem 0x%x 32 0x%x' % (pypu_base + 0x10, len(pyc)))
    for i, b in enumerate(pyc):
        send(b'devmem 0x%x 8 0x%x' % (pypu_base + 0x100 + i, b))
    send(b'devmem 0x%x 32 1' % (pypu_base + 0xc))

    flag = bytearray(flag_length)
    for i in range(flag_length):
        send(b'devmem 0x%x 8' % (pypu_base + 0x1000 + i))
        flag[i] = int(p.recvline(), 0)

    send(b'poweroff -f')
    p.wait()

success(f'Flag: {flag.decode()}')
