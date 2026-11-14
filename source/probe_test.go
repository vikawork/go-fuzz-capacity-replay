// Source: https://developers.googleblog.com/catch-go-bugs-that-fuzzing-misses-with-gemini-and-a-constraint-solver/
// Job-authored capacity probe; no parser call or seed corpus is used.
package demo

import (
	"fmt"
	"os"
	"sort"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"
)

const (
	probeMagic       = uint64(0x475350524f424531)
	probeVersion     = uint64(1)
	probeHeaderBytes = 128
	probeSlots       = 16384
	probeSlotBytes   = 16
	probeFileBytes   = probeHeaderBytes + probeSlots*probeSlotBytes
)

// The Linux/amd64 mmap is shared by the coordinator and all fuzz workers.
// Header uint64s: magic, version, calls, equal, greater, less, overflow, reserved.
// Each slot holds uint64 key and count. key = 1 + 2*capacity + relation, where
// relation is 0 for cap==len and 1 for cap>len. A single atomic count increment
// commits a callback; summaries derive canonical totals and relation counts from
// these slots. Header counters are cross-checks, not the canonical totals: a
// forced process kill between atomics cannot corrupt the slot accounting.
// All integers use the native little-endian representation of the pinned target.
type probeMap struct{ memory []byte }

func probeFilePath(t testing.TB) string {
	t.Helper()
	path := os.Getenv("GOSOLVER_PROBE_FILE")
	if path == "" {
		t.Skip("GOSOLVER_PROBE_FILE is unset")
	}
	return path
}

func (p probeMap) word(offset int) *uint64 {
	return (*uint64)(unsafe.Pointer(&p.memory[offset]))
}

func openProbe(t testing.TB) probeMap {
	t.Helper()
	file, err := os.OpenFile(probeFilePath(t), os.O_RDWR, 0)
	if err != nil {
		t.Fatal("cannot open the preallocated probe file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != int64(probeFileBytes) {
		t.Fatal("probe file has the wrong size")
	}
	memory, err := syscall.Mmap(int(file.Fd()), 0, probeFileBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal("cannot map the probe file")
	}
	p := probeMap{memory}
	if atomic.LoadUint64(p.word(0)) != probeMagic || atomic.LoadUint64(p.word(8)) != probeVersion {
		syscall.Munmap(memory)
		t.Fatal("probe file has the wrong format; initialize it first")
	}
	t.Cleanup(func() {
		if err := syscall.Munmap(memory); err != nil {
			t.Error("cannot unmap the probe file")
		}
	})
	return p
}

func TestProbeFileInit(t *testing.T) {
	file, err := os.OpenFile(probeFilePath(t), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal("cannot create the probe file")
	}
	defer file.Close()
	if err := file.Truncate(int64(probeFileBytes)); err != nil {
		t.Fatal("cannot preallocate the probe file")
	}
	memory, err := syscall.Mmap(int(file.Fd()), 0, probeFileBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal("cannot initialize the probe file mapping")
	}
	p := probeMap{memory}
	atomic.StoreUint64(p.word(0), probeMagic)
	atomic.StoreUint64(p.word(8), probeVersion)
	if err := syscall.Munmap(memory); err != nil {
		t.Fatal("cannot unmap the initialized probe file")
	}
}

func (p probeMap) record(length, capacity int) {
	relation, headerOffset := uint64(0), 24
	if capacity > length {
		relation, headerOffset = 1, 32
	} else if capacity < length {
		// A Go slice cannot have cap<len. Preserve a diagnostic if that invariant
		// is ever violated rather than silently classifying the sample.
		atomic.AddUint64(p.word(40), 1)
		return
	}
	key := uint64(capacity)*2 + relation + 1
	index := (key * 11400714819323198485) & (probeSlots - 1)
	for attempts := 0; attempts < probeSlots; attempts++ {
		offset := probeHeaderBytes + int(index)*probeSlotBytes
		existing := atomic.LoadUint64(p.word(offset))
		if existing == 0 && atomic.CompareAndSwapUint64(p.word(offset), 0, key) {
			existing = key
		}
		if existing == key {
			// No process-local buffering: every committed callback is immediately
			// visible in the shared mapping, including the empty baseline callback.
			atomic.AddUint64(p.word(offset+8), 1)
			atomic.AddUint64(p.word(headerOffset), 1)
			atomic.AddUint64(p.word(16), 1)
			return
		}
		index = (index + 1) & (probeSlots - 1)
	}
	atomic.AddUint64(p.word(48), 1)
}

func FuzzCapacityProbe(f *testing.F) {
	p := openProbe(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		p.record(len(data), cap(data))
	})
}

func TestProbeFileSummary(t *testing.T) {
	p := openProbe(t)
	type bin struct {
		Capacity uint64 `json:"capacity"`
		Calls    uint64 `json:"calls"`
		Equal    uint64 `json:"cap_eq_len"`
		Greater  uint64 `json:"cap_gt_len"`
	}
	bins := make(map[uint64]*bin)
	var calls, equal, greater uint64
	for slot := 0; slot < probeSlots; slot++ {
		offset := probeHeaderBytes + slot*probeSlotBytes
		key := atomic.LoadUint64(p.word(offset))
		count := atomic.LoadUint64(p.word(offset + 8))
		if key == 0 || count == 0 {
			continue
		}
		capacity, relation := (key-1)/2, (key-1)%2
		item := bins[capacity]
		if item == nil {
			item = &bin{Capacity: capacity}
			bins[capacity] = item
		}
		item.Calls += count
		calls += count
		if relation == 0 {
			item.Equal += count
			equal += count
		} else {
			item.Greater += count
			greater += count
		}
	}
	histogram := make([]bin, 0, len(bins))
	for _, item := range bins {
		histogram = append(histogram, *item)
	}
	sort.Slice(histogram, func(i, j int) bool { return histogram[i].Capacity < histogram[j].Capacity })
	var minimum, median, maximum, cumulative, largeCalls uint64
	for index, item := range histogram {
		if index == 0 {
			minimum = item.Capacity
		}
		maximum = item.Capacity
		if cumulative < (calls+1)/2 && cumulative+item.Calls >= (calls+1)/2 {
			median = item.Capacity
		}
		cumulative += item.Calls
		// Explicit broad window around the article's approximately 100MB buffer.
		if item.Capacity >= 64*1024*1024 && item.Capacity <= 128*1024*1024 {
			largeCalls += item.Calls
		}
	}
	overflow, less := atomic.LoadUint64(p.word(48)), atomic.LoadUint64(p.word(40))
	headerCalls := atomic.LoadUint64(p.word(16))
	headerEqual, headerGreater := atomic.LoadUint64(p.word(24)), atomic.LoadUint64(p.word(32))
	writeRecord(t, struct {
		Kind               string `json:"kind"`
		Calls              uint64 `json:"calls"`
		Equal              uint64 `json:"cap_eq_len"`
		Greater            uint64 `json:"cap_gt_len"`
		Less               uint64 `json:"cap_lt_len"`
		Minimum            uint64 `json:"capacity_min"`
		Median             uint64 `json:"capacity_median"`
		Maximum            uint64 `json:"capacity_max"`
		LargeCalls         uint64 `json:"capacity_64_to_128_mib_calls"`
		HistogramSum       uint64 `json:"histogram_sum"`
		Overflow           uint64 `json:"table_overflow"`
		HeaderCalls        uint64 `json:"header_calls"`
		HeaderEqual        uint64 `json:"header_cap_eq_len"`
		HeaderGreater      uint64 `json:"header_cap_gt_len"`
		HeaderConsistent   bool   `json:"header_consistent"`
		Valid              bool   `json:"valid"`
		Histogram          []bin  `json:"capacity_histogram"`
	}{"capacity_probe", calls, equal, greater, less, minimum, median, maximum,
		largeCalls, cumulative, overflow, headerCalls, headerEqual, headerGreater,
		headerCalls == calls && headerEqual == equal && headerGreater == greater,
		overflow == 0 && less == 0 && cumulative == calls && calls == equal+greater, histogram})
	if overflow != 0 || less != 0 {
		t.Fatal(fmt.Sprintf("invalid probe: overflow=%d cap_lt_len=%d", overflow, less))
	}
}
