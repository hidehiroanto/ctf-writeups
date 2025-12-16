#!/usr/bin/env python3

from angr import Project
from pwn import *

naughty_or_nice = '/challenge/naughty-or-nice'
list_dir = '/tmp/list'

if not os.path.isdir(list_dir):
    os.mkdir(list_dir)

for digest in sorted(os.listdir(naughty_or_nice)):
    if digest in os.listdir(list_dir):
        password = read(os.path.join(list_dir, digest))
    else:
        simgr = Project(os.path.join(naughty_or_nice, digest)).factory.simgr()
        simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1), avoid=lambda s: b'Wrong' in s.posix.dumps(1))
        password = simgr.found[0].posix.dumps(0).strip(b'\0')
        write(os.path.join(list_dir, digest), password)
    info(f'{digest}: {password.strip().decode()}')

with process(['/challenge/run', list_dir], level='error') as p:
    success(f'Flag: {p.recvall().split()[-1].decode()}')
