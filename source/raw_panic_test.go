// Job-authored: calls the published parser with the published counterexample and lets the panic through.
package demo

import "testing"

func TestRawPanic(t *testing.T) {
	ParseTwoChunkFrame(frame(59, 59, 48, 236))
}
