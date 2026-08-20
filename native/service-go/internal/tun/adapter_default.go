//go:build !windows

package tun

// Open reports that no adapter implementation is bundled for this OS. Keeping a
// stub here lets the rest of the service compile and be tested on any platform.
func Open(Config) (Adapter, error) {
	return nil, ErrUnsupportedPlatform
}

func available() error {
	return ErrUnsupportedPlatform
}
