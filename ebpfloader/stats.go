package ebpfloader

// Stats reports what the kernel side has seen.
//
// Dropped is the number the operator actually needs: it counts events the
// kernel could not enqueue because userspace was not draining fast enough.
// Those events are gone — not delayed — so a non-zero value means this tool's
// output is incomplete for that window. Reporting it is the difference between
// a monitor that is honest about its blind spots and one that quietly
// under-reports.
type Stats struct {
	Events  uint64
	Dropped uint64
}
