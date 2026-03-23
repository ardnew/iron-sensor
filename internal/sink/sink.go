package sink

import "io"

// Sink is the destination for serialized events.
type Sink interface {
	io.Writer
	Close() error
}
