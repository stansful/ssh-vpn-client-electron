package platform

import "testing"

func TestSupportsPrivilegedServiceOnlyForPackagedWindowsTargets(t *testing.T) {
	for _, test := range []struct {
		platform string
		arch     string
		want     bool
	}{
		{platform: "windows", arch: "x64", want: true},
		{platform: "windows", arch: "arm64", want: true},
		{platform: "windows", arch: "ia32", want: false},
		{platform: "macos", arch: "arm64", want: false},
		{platform: "linux", arch: "x64", want: false},
	} {
		if got := supportsPrivilegedService(test.platform, test.arch); got != test.want {
			t.Fatalf("supportsPrivilegedService(%q, %q)=%v, want %v", test.platform, test.arch, got, test.want)
		}
	}
}
