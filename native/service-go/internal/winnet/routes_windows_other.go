//go:build windows && !(amd64 || arm64)

package winnet

// Routes is only implemented for the 64-bit layouts this helper is built for.
func Routes() ([]Route, error) { return nil, ErrUnsupportedPlatform }
