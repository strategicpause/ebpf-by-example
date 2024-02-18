package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	"github.com/iovisor/gobpf"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
	char comm[128];
	char filename[128];
} chroot_event_t;

BPF_PERF_OUTPUT(chroot_events);

int kprobe__sys_chroot(struct pt_regs *ctx, const char *filename)
{
	u64 pid = bpf_get_current_pid_tgid();
	chroot_event_t event = {
		.pid = pid >> 32,
	};
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
	chroot_events.perf_submit(ctx, &event, sizeof(event));
	return 0;
}
`

type chrootEvent struct {
	Pid      uint32
	Comm     [128]byte
	Filename [128]byte
}

func main() {
	m := bpf.NewBpfModule(source, []string{})
	defer m.Close()

	chrootKprobe, err := m.LoadKprobe("kprobe__sys_chroot")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kprobe__sys_chroot: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKprobe("sys_chroot", chrootKprobe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe__sys_chroot: %s\n", err)
		os.Exit(1)
	}

	chrootEventsTable := bpf.NewBpfTable(0, m)

	chrootEventsChannel := make(chan []byte)

	chrootPerfMap, err := bpf.InitPerfMap(chrootEventsTable, chrootEventsChannel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var chrootE chrootEvent
		for {
			data := <-chrootEventsChannel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &chrootE)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to decode received chroot event data: %s\n", err)
				continue
			}
			comm := (*C.char)(unsafe.Pointer(&chrootE.Comm))
			filename := (*C.char)(unsafe.Pointer(&chrootE.Filename))
			fmt.Printf("pid %d %s called chroot(2) on %s\n", chrootE.Pid, C.GoString(comm), C.GoString(filename))
		}
	}()

	chrootPerfMap.Start()
	<-sig
	chrootPerfMap.Stop()
}
