#!/usr/bin/python3
from bcc import BPF
import ctypes as ct
from time import sleep

program = r"""
BPF_HASH(counter_table, int, u64);


int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&opcode);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&opcode, &counter);
    return 0;
}

"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(3)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)