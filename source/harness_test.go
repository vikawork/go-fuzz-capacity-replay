// Source: https://developers.googleblog.com/catch-go-bugs-that-fuzzing-misses-with-gemini-and-a-constraint-solver/
// Job-authored measurement wrappers around the separately preserved parser.
package demo

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
)

type parseOutcome struct {
	Panicked bool   `json:"panicked"`
	Panic    string `json:"panic,omitempty"`
	Accepted bool   `json:"accepted"`
	Header   []byte `json:"-"`
	Body     []byte `json:"-"`
}

func invokeParser(data []byte) (out parseOutcome) {
	defer func() {
		if problem := recover(); problem != nil {
			out.Panicked = true
			out.Panic = fmt.Sprint(problem)
		}
	}()
	out.Header, out.Body = ParseTwoChunkFrame(data)
	out.Accepted = out.Header != nil || out.Body != nil
	return out
}

func writeRecord(t *testing.T, value any) {
	t.Helper()
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func headerByte(t *testing.T, name string, fallback uint8) uint8 {
	t.Helper()
	value, exists := os.LookupEnv(name)
	if !exists {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		t.Fatalf("%s must be a decimal uint8", name)
	}
	return uint8(parsed)
}

func frame(length, capacity int, header, body uint8) []byte {
	data := make([]byte, length, capacity)
	data[0], data[1], data[2], data[3] = 0xA5, 0x5A, header, body
	return data
}

func TestCounterexample(t *testing.T) {
	header, body := headerByte(t, "HLEN", 48), headerByte(t, "BLEN", 236)
	cases := []struct {
		name string
		h, b uint8
	}{{"solver_model", header, body}}
	if header != 48 || body != 236 {
		cases = append(cases, struct {
			name string
			h, b uint8
		}{"published_counterexample", 48, 236})
	}
	for _, example := range cases {
		for _, capacity := range []int{59, 1024} {
			// make zero-initializes the complete backing array. The visible bytes
			// are identical; successful reads beyond len therefore return zeroes.
			data := frame(59, capacity, example.h, example.b)
			out := invokeParser(data)
			writeRecord(t, struct {
				Kind      string `json:"kind"`
				Case      string `json:"case"`
				Length    int    `json:"length"`
				Capacity  int    `json:"capacity"`
				HeaderLen uint8  `json:"header_len"`
				BodyLen   uint8  `json:"body_len"`
				parseOutcome
				ReturnedHeaderLen int    `json:"returned_header_len"`
				ReturnedBodyLen   int    `json:"returned_body_len"`
				HeaderHex         string `json:"header_hex"`
				BodyHex           string `json:"body_hex"`
			}{"counterexample", example.name, len(data), cap(data), example.h, example.b,
				out, len(out.Header), len(out.Body), hex.EncodeToString(out.Header), hex.EncodeToString(out.Body)})
		}
	}
}

func TestExhaustive(t *testing.T) {
	for _, length := range []int{32, 59, 64, 128, 256} {
		panics, accepted, rejected := 0, 0, 0
		for h := 0; h < 256; h++ {
			for b := 0; b < 256; b++ {
				// A new allocation for each pair keeps len == cap explicit.
				out := invokeParser(frame(length, length, uint8(h), uint8(b)))
				switch {
				case out.Panicked:
					panics++
				case out.Accepted:
					accepted++
				default:
					rejected++
				}
			}
		}
		writeRecord(t, struct {
			Kind     string `json:"kind"`
			Length   int    `json:"length"`
			Capacity int    `json:"capacity"`
			Pairs    int    `json:"pairs"`
			Panics   int    `json:"panics"`
			Accepted int    `json:"accepted"`
			Rejected int    `json:"rejected"`
		}{"exhaustive", length, length, 65536, panics, accepted, rejected})
	}
}

// The callback below is the article's unseeded harness, as published. The test
// function name and surrounding module are job-authored. There are no f.Add calls.
func FuzzTwoChunk(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseTwoChunkFrame(data)
	})
}

// Job-authored duplicate with the article's full slice expression, as published.
func FuzzTwoChunkClipped(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		data = data[:len(data):len(data)]
		ParseTwoChunkFrame(data)
	})
}
