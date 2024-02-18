#!/usr/bin/python

from bcc import BPF
import time

program = r"""
// Macro which is used to define a hash table map.
BPF_HASH(counter_table);

int hello(void *ctx) {
	// Obtain the user ID that is running the process that triggered this kprobe event. Get the lower 32-bits of the value returned.
	u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	u64 *p = counter_table.lookup(&uid);
	u64 counter = 0;
	if (p != 0) {
		counter = *p;
	}
	counter++;
	counter_table.update(&uid, &counter);

	return 0;	
}

"""

b = BPF(text=program)
#exec_syscall = b.get_syscall_fnname("execve")
#b.attach_kprobe(event=exec_syscall, fn_name="hello")

#openat_syscall = b.get_syscall_fnname("openat")
#b.attach_kprobe(event=openat_syscall, fn_name="hello")

b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
	time.sleep(2)
	s = ""
	for k, v in b["counter_table"].items():
		s += f"ID {k.value}: {v.value}\t"
	print(s)