package events

import (
	"iron-sensor/internal/sink"
	"sync"
)

// Emitter writes serialized events to a sink.
type Emitter struct {
	sink        sink.Sink
	mu          sync.Mutex
	minSeverity *int
}

func NewEmitter(s sink.Sink, minSeverity *int) *Emitter {
	return &Emitter{sink: s, minSeverity: minSeverity}
}

func (e *Emitter) Emit(ev Event) error {
	if e.minSeverity != nil && ev.Category != "agent_lifecycle" {
		if ev.Severity > *e.minSeverity {
			return nil
		}
	}

	data, err := Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	e.mu.Lock()
	defer e.mu.Unlock()
	_, err = e.sink.Write(data)
	return err
}

func (e *Emitter) Close() error {
	return e.sink.Close()
}
