from pwn import *


p = process('./main')
gdb.attach(p)
