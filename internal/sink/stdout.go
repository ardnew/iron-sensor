package sink

import "os"

// StdoutSink writes events to stdout.
type StdoutSink struct{}

func NewStdoutSink() *StdoutSink {
	return &StdoutSink{}
}

func (s *StdoutSink) Write(p []byte) (int, error) {
	return os.Stdout.Write(p)
}

func (s *StdoutSink) Close() error {
	return nil
}
