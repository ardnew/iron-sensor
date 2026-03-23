package sink

import (
	"iron-sensor/internal/config"

	"gopkg.in/natefinch/lumberjack.v2"
)

// FileSink writes events to a rotating log file via lumberjack.
type FileSink struct {
	logger *lumberjack.Logger
}

func NewFileSink(cfg config.FileSinkConfig) *FileSink {
	return &FileSink{
		logger: &lumberjack.Logger{
			Filename:   cfg.OutputPath,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			Compress:   cfg.Compress,
		},
	}
}

func (f *FileSink) Write(p []byte) (int, error) {
	return f.logger.Write(p)
}

func (f *FileSink) Close() error {
	return f.logger.Close()
}
