package winroute

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The journal lives in a folder the signed-in user can write to, and it is
// replayed by an elevated process. Anything in it is therefore untrusted input,
// and "run whatever argv the file lists" was a way to have the elevated helper
// run any program at all. What may be run is limited to exactly the netsh
// invocations Plan renders: the same words in the same order, every value
// parsed and rendered back to the identical text. A journal that holds
// anything else was not written by this program and is refused whole.

// netshProgram is the only program the manager runs. Plans and journals name it
// bare; execRunner runs it from the system directory, never through PATH.
const netshProgram = "netsh"

type valueKind int

const (
	literalValue valueKind = iota
	// indexValue is an interface index: decimal, non-zero, no leading zeros.
	indexValue
	// addressValue is an address of the command's family, in canonical form.
	addressValue
	// addressWithLengthValue is the IPv6 address and prefix length that
	// `set address` assigns, "fd7a:c0de:5417::2/64".
	addressWithLengthValue
	// capturePrefixValue is one of the two halves of the address space.
	capturePrefixValue
	// hostPrefixValue is a single address: /32 or /128.
	hostPrefixValue
)

type commandParameter struct {
	key     string
	kind    valueKind
	literal string
}

// commandShape is one form Plan renders, after "netsh interface <family>".
type commandShape struct {
	// family is "ipv4" or "ipv6", or empty when the form exists for both.
	family     string
	verb       string
	object     string
	parameters []commandParameter
	// undo marks the forms that revert a change. Only these may appear in a
	// journal.
	undo bool
}

func literal(key string, value string) commandParameter {
	return commandParameter{key: key, kind: literalValue, literal: value}
}

func typed(key string, kind valueKind) commandParameter {
	return commandParameter{key: key, kind: kind}
}

// commandShapes mirrors plan.go. A form added there has to be added here as
// well, or Apply refuses the plan before it touches the routing table.
var commandShapes = []commandShape{
	// The adapter's IPv4 address, and its reset.
	{family: "ipv4", verb: "set", object: "address", parameters: []commandParameter{
		typed("name", indexValue), literal("source", "static"), typed("address", addressValue),
		typed("mask", addressValue), literal("gateway", "none"), literal("store", "active"),
	}},
	{family: "ipv4", verb: "set", object: "address", undo: true, parameters: []commandParameter{
		typed("name", indexValue), literal("source", "dhcp"), literal("store", "active"),
	}},
	// The adapter's IPv6 address, and its removal.
	{family: "ipv6", verb: "set", object: "address", parameters: []commandParameter{
		typed("interface", indexValue), typed("address", addressWithLengthValue), literal("store", "active"),
	}},
	{family: "ipv6", verb: "delete", object: "address", undo: true, parameters: []commandParameter{
		typed("interface", indexValue), typed("address", addressValue), literal("store", "active"),
	}},
	// The adapter's interface metric, and its reset.
	{verb: "set", object: "interface", parameters: []commandParameter{
		typed("interface", indexValue), literal("metric", "1"), literal("store", "active"),
	}},
	{verb: "set", object: "interface", undo: true, parameters: []commandParameter{
		typed("interface", indexValue), literal("metric", "automatic"), literal("store", "active"),
	}},
	// The capture routes.
	{verb: "add", object: "route", parameters: []commandParameter{
		typed("prefix", capturePrefixValue), typed("interface", indexValue), literal("metric", "1"), literal("store", "active"),
	}},
	{verb: "delete", object: "route", undo: true, parameters: []commandParameter{
		typed("prefix", capturePrefixValue), typed("interface", indexValue), literal("store", "active"),
	}},
	// The transport server's host route through its physical gateway.
	{verb: "add", object: "route", parameters: []commandParameter{
		typed("prefix", hostPrefixValue), typed("interface", indexValue), typed("nexthop", addressValue),
		literal("metric", "1"), literal("store", "active"),
	}},
	{verb: "delete", object: "route", undo: true, parameters: []commandParameter{
		typed("prefix", hostPrefixValue), typed("interface", indexValue), typed("nexthop", addressValue),
		literal("store", "active"),
	}},
}

var capturePrefixes = map[string][]string{
	"ipv4": {"0.0.0.0/1", "128.0.0.0/1"},
	"ipv6": {"::/1", "8000::/1"},
}

// netshCommand is a validated invocation.
type netshCommand struct {
	shape  *commandShape
	family string
	// index is the interface every form names exactly once.
	index uint32
	// arguments are the key=value words after the verb and object.
	arguments []string
}

// value is the text of one key=value argument, empty when the form has none.
func (c netshCommand) value(key string) string {
	for _, argument := range c.arguments {
		if name, value, ok := strings.Cut(argument, "="); ok && name == key {
			return value
		}
	}
	return ""
}

// routeTarget is the route a route form names: its prefix and, for a host
// route, its next hop. ok is false for the forms that change an address or a
// metric instead.
func (c netshCommand) routeTarget() (prefix netip.Prefix, nextHop netip.Addr, ok bool) {
	if c.shape.object != "route" {
		return netip.Prefix{}, netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(c.value("prefix"))
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, false
	}
	if raw := c.value("nexthop"); raw != "" {
		if nextHop, err = netip.ParseAddr(raw); err != nil {
			return netip.Prefix{}, netip.Addr{}, false
		}
	}
	return prefix, nextHop, true
}

// pinned reports whether the command can only ever touch the route it was
// written for: a host route deleted by prefix, interface and next hop. Run
// against an interface that has since taken over the index, it finds nothing to
// delete. Every other form would act on whatever that interface now is.
func (c netshCommand) pinned() bool {
	if c.shape.object != "route" {
		return false
	}
	for _, parameter := range c.shape.parameters {
		if parameter.key == "nexthop" {
			return true
		}
	}
	return false
}

// parseNetsh accepts argv only if it is one of the forms Plan renders.
func parseNetsh(argv []string) (netshCommand, error) {
	if len(argv) < 5 || argv[0] != netshProgram || argv[1] != "interface" || (argv[2] != "ipv4" && argv[2] != "ipv6") {
		return netshCommand{}, unexpectedCommand(argv)
	}
	family := argv[2]
	for position := range commandShapes {
		shape := &commandShapes[position]
		if shape.family != "" && shape.family != family {
			continue
		}
		if argv[3] != shape.verb || argv[4] != shape.object || len(argv) != 5+len(shape.parameters) {
			continue
		}
		if index, ok := shape.match(family, argv[5:]); ok {
			return netshCommand{shape: shape, family: family, index: index, arguments: argv[5:]}, nil
		}
	}
	return netshCommand{}, unexpectedCommand(argv)
}

func (s *commandShape) match(family string, arguments []string) (uint32, bool) {
	var index uint32
	for position, parameter := range s.parameters {
		key, value, ok := strings.Cut(arguments[position], "=")
		if !ok || key != parameter.key {
			return 0, false
		}
		switch parameter.kind {
		case literalValue:
			ok = value == parameter.literal
		case indexValue:
			index, ok = parseInterfaceIndex(value)
		case addressValue:
			ok = canonicalAddress(family, value)
		case addressWithLengthValue:
			ok = canonicalAddressWithLength(family, value)
		case capturePrefixValue:
			ok = false
			for _, prefix := range capturePrefixes[family] {
				ok = ok || value == prefix
			}
		case hostPrefixValue:
			ok = canonicalHostPrefix(family, value)
		default:
			ok = false
		}
		if !ok {
			return 0, false
		}
	}
	return index, index != 0
}

func parseInterfaceIndex(value string) (uint32, bool) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return 0, false
	}
	return uint32(parsed), true
}

// familyAddress reports whether address belongs to family. Zones are refused:
// the plan never renders one, and one would carry free text into the command.
func familyAddress(family string, address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	if family == "ipv4" {
		return address.Is4()
	}
	return address.Is6() && !address.Is4In6()
}

func canonicalAddress(family string, value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && familyAddress(family, address) && address.String() == value
}

func canonicalAddressWithLength(family string, value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && familyAddress(family, prefix.Addr()) && prefix.Bits() > 0 && prefix.String() == value
}

func canonicalHostPrefix(family string, value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && familyAddress(family, prefix.Addr()) && prefix.IsSingleIP() && prefix.String() == value
}

func unexpectedCommand(argv []string) error {
	rendered := strings.Join(argv, " ")
	if len(rendered) > 200 {
		rendered = rendered[:200] + "..."
	}
	return fmt.Errorf("%q is not a routing command this program writes", rendered)
}

// validateOperation checks both halves of a planned operation: the change is
// one of the forms that apply, its undo one of the forms that revert, and both
// name the same interface.
func validateOperation(operation Operation) error {
	apply, err := parseNetsh(operation.Apply)
	if err != nil {
		return err
	}
	undo, err := parseUndo(operation.Undo)
	if err != nil {
		return err
	}
	if apply.shape.undo || apply.family != undo.family || apply.index != undo.index {
		return fmt.Errorf("%q does not undo %q", strings.Join(operation.Undo, " "), strings.Join(operation.Apply, " "))
	}
	return nil
}

// parseUndo accepts argv only if it is a form that reverts a change.
func parseUndo(argv []string) (netshCommand, error) {
	command, err := parseNetsh(argv)
	if err != nil {
		return netshCommand{}, err
	}
	if !command.shape.undo {
		return netshCommand{}, fmt.Errorf("%q makes a change instead of undoing one", strings.Join(argv, " "))
	}
	return command, nil
}
