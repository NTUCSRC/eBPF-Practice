#!/usr/bin/python3
from bcc import BPF
from time import sleep
import ctypes

program = r"""
BPF_HASH(counter_table, int, u64);

int openFile(void *ctx) {
    int index = 257;
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&index);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&index, &counter);
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("openat")
print(syscall)
b.attach_kprobe(event=syscall, fn_name="openFile")

while True:
    sleep(3)
    key = ctypes.c_int(257)
    for key in b["counter_table"]:
        print(f"sys_openat: {b['counter_table'][key].value}")