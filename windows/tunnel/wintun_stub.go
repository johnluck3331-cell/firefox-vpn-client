//go:build !windows

package tunnel

import "errors"

// NewWintunAdapter is unavailable off-Windows; the service and dataplane
// tools build for Linux only against FakeAdapter.
type WintunAdapter struct{}

var errWindowsOnly = errors.New("tunnel: Wintun requires Windows")

func (*WintunAdapter) Create(AdapterConfig) error                { return errWindowsOnly }
func (*WintunAdapter) Open(string) error                         { return errWindowsOnly }
func (*WintunAdapter) LUID() string                              { return "" }
func (*WintunAdapter) StartSession(LayerConfig) (Session, error) { return nil, errWindowsOnly }
func (*WintunAdapter) Delete() error                             { return errWindowsOnly }
func (*WintunAdapter) Close() error                              { return nil }

// WintunAvailable reports the platform limitation on non-Windows hosts.
func WintunAvailable() error { return errWindowsOnly }

// DriverVersion is a no-op stub off-Windows.
func DriverVersion() (uint32, error) { return 0, errWindowsOnly }
