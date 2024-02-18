#!/usr/bin/python

from bcc import BPF
import time

program = r"""
// Macro which is used to create a map that will be used to pass messages from kernel to user space.
BPF_PERF_OUTPUT(output);

struct data_t {
	int pid;
	int uid;
	char command[16];
	char message[12];
};

int hello(void *ctx) {
	struct data_t data = {};
	char odd_message[12] = "Hello World";
	char even_message[12] = "Foo bar";

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	// Fetch the name of the executable that's running in the process that made the execve syscall.
	bpf_get_current_comm(&data.command, sizeof(data.command));
	// Copies the message to the data structure.
	if data.pid % 2 == 0 {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), even_message);
	} else {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), odd_message);
	}
	
	// Put the data into the map
	output.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
"""

b = BPF(text=program)
execve_syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_syscall, fn_name="hello")

def print_event(cpu, data, size):
	data = b["output"].event(data)
	print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

b["output"].open_perf_buffer(print_event)
while True:
	b.perf_buffer_poll()