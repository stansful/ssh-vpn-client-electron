package platform

import "fmt"

// describeTUNReadiness turns the two independent prerequisites for a tunnel
// adapter into an answer the user can act on.
//
// Running as the built-in Administrator account is not the same as running
// elevated: with UAC on, the process still gets a filtered token unless it was
// started with "Run as administrator". A single "start as administrator"
// therefore looks wrong to exactly the user it is aimed at, and says nothing at
// all to the one whose DLL is simply in the wrong folder - which is why the two
// causes are reported separately, and together when both apply.
func describeTUNReadiness(elevated bool, driverErr error) (bool, string) {
	const notElevated = "this process is not elevated; running as an administrator account is not enough, start the application with \"Run as administrator\""

	switch {
	case elevated && driverErr == nil:
		return true, ""
	case !elevated && driverErr != nil:
		return false, fmt.Sprintf("%s. Also, %s", notElevated, driverErr)
	case !elevated:
		return false, notElevated
	default:
		return false, driverErr.Error()
	}
}
