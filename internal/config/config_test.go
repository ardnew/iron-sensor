package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	require.Equal(t, "file", cfg.SinkType)
	require.Equal(t, "/var/log/iron/sensor/events.json", cfg.FileSink.OutputPath)
	require.Equal(t, 100, cfg.FileSink.MaxSize)
	require.Equal(t, 5, cfg.FileSink.MaxBackups)
	require.True(t, cfg.FileSink.Compress)
	require.Nil(t, cfg.Rules.MinSeverity)
	require.Nil(t, cfg.Rules.Overrides)
}

func TestLoad_FullConfig(t *testing.T) {
	yaml := `
sink_type: stdout
file_sink:
  output_path: /tmp/events.json
  max_size: 50
  max_backups: 3
  compress: false
rules:
  min_severity: 1
  overrides:
    shell_spawn:
      severity: 0
      enabled: true
    package_manager:
      enabled: false
`
	cfg := loadFromString(t, yaml)

	require.Equal(t, "stdout", cfg.SinkType)
	require.Equal(t, "/tmp/events.json", cfg.FileSink.OutputPath)
	require.Equal(t, 50, cfg.FileSink.MaxSize)
	require.Equal(t, 3, cfg.FileSink.MaxBackups)
	require.False(t, cfg.FileSink.Compress)

	require.NotNil(t, cfg.Rules.MinSeverity)
	require.Equal(t, 1, *cfg.Rules.MinSeverity)

	ss := cfg.Rules.Overrides["shell_spawn"]
	require.NotNil(t, ss.Severity)
	require.Equal(t, 0, *ss.Severity)
	require.NotNil(t, ss.Enabled)
	require.True(t, *ss.Enabled)

	pm := cfg.Rules.Overrides["package_manager"]
	require.Nil(t, pm.Severity)
	require.NotNil(t, pm.Enabled)
	require.False(t, *pm.Enabled)
}

func TestLoad_PartialConfig(t *testing.T) {
	yaml := `
file_sink:
  max_size: 200
`
	cfg := loadFromString(t, yaml)

	require.Equal(t, "file", cfg.SinkType)                                   // default
	require.Equal(t, "/var/log/iron/sensor/events.json", cfg.FileSink.OutputPath) // default
	require.Equal(t, 200, cfg.FileSink.MaxSize)
	require.Equal(t, 5, cfg.FileSink.MaxBackups) // default
	require.True(t, cfg.FileSink.Compress)        // default
	require.Nil(t, cfg.Rules.MinSeverity)
}

func TestLoad_EmptyFile(t *testing.T) {
	cfg := loadFromString(t, "")

	require.Equal(t, "file", cfg.SinkType)
	require.Equal(t, 100, cfg.FileSink.MaxSize)
	require.Equal(t, 5, cfg.FileSink.MaxBackups)
	require.True(t, cfg.FileSink.Compress)
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(":\n  :\n  - [invalid"), 0o644))
	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing config")
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading config")
}

func loadFromString(t *testing.T, content string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	cfg, err := Load(path)
	require.NoError(t, err)
	return cfg
}
