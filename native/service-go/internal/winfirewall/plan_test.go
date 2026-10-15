package winfirewall

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func filtersOf(filters []Filter, family Family, direction Direction) []Filter {
	var selected []Filter
	for _, filter := range filters {
		if filter.Family == family && filter.Direction == direction {
			selected = append(selected, filter)
		}
	}
	return selected
}

func blockedKinds(filters []Filter) []ConditionKind {
	var kinds []ConditionKind
	for _, filter := range filters {
		if filter.Action == ActionBlock {
			kinds = append(kinds, filter.Condition.Kind)
		}
	}
	slices.Sort(kinds)
	return kinds
}

func reachableOf(filters []Filter) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, filter := range filters {
		if filter.Condition.Kind == ConditionRemotePrefixes {
			prefixes = append(prefixes, filter.Condition.Prefixes...)
		}
	}
	return prefixes
}

func TestPlanBlocksOnlyAfterEveryExemption(t *testing.T) {
	plan := NewPlan(42, true, nil, nil)
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, direction := range []Direction{Outbound, Inbound} {
			filters := filtersOf(plan.Filters(), family, direction)
			// Outbound refuses UDP and TCP; inbound only UDP - an ICE check a
			// peer sends to the card - since incoming TCP is a server the
			// user runs.
			want := []ConditionKind{ConditionUDP}
			if direction == Outbound {
				want = []ConditionKind{ConditionUDP, ConditionTCP}
			}
			if got := blockedKinds(filters); !slices.Equal(got, want) {
				t.Fatalf("IPv%d direction %d blocks %v, want %v", family, direction, got, want)
			}
			kinds := map[ConditionKind]bool{}
			for _, filter := range filters {
				if filter.Action == ActionPermit {
					kinds[filter.Condition.Kind] = true
					if filter.Weight <= weightBlock {
						t.Fatalf("permit %q does not outweigh the blocks", filter.Name)
					}
				}
			}
			// Without the tunnel permit the blocks would catch the adapter's
			// own traffic; without the helper permit, every direct flow;
			// without the services permit, Windows and other VPN daemons.
			for _, kind := range []ConditionKind{ConditionHelper, ConditionServices, ConditionLoopback, ConditionTunnel,
				ConditionRemotePrefixes, ConditionRemotePorts} {
				if !kinds[kind] {
					t.Fatalf("IPv%d direction %d is missing the exemption of kind %d", family, direction, kind)
				}
			}
		}
	}
}

func TestPlanNamesEveryFilterApart(t *testing.T) {
	names := map[string]bool{}
	for _, filter := range NewPlan(42, true, nil, nil).Filters() {
		if filter.Condition.Kind == ConditionRemotePrefixes {
			continue // split over several filters of one name
		}
		if names[filter.Name] {
			t.Fatalf("two filters are called %q", filter.Name)
		}
		names[filter.Name] = true
	}
}

func TestPlanLeavesAnUncapturedFamilyAlone(t *testing.T) {
	plan := NewPlan(42, false, nil, nil)
	for _, direction := range []Direction{Outbound, Inbound} {
		if filters := filtersOf(plan.Filters(), FamilyIPv6, direction); len(filters) != 0 {
			t.Fatalf("IPv6 is not captured, yet it is guarded: %+v", filters)
		}
		if filters := filtersOf(plan.Filters(), FamilyIPv4, direction); len(filters) == 0 {
			t.Fatal("IPv4 is not guarded")
		}
	}
}

func TestPlanExemptsServersLocalAndRoutedNetworks(t *testing.T) {
	plan := NewPlan(42, true,
		[]netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("::ffff:198.51.100.4"), netip.MustParseAddr("2001:db8::9")},
		[]netip.Prefix{
			netip.MustParsePrefix("81.2.69.17/24"),       // a LAN on public addresses
			netip.MustParsePrefix("195.208.0.0/16"),      // a persistent route, or another VPN's
			netip.MustParsePrefix("2a02:6b8:1:2::17/64"), // an on-link IPv6 prefix
			netip.MustParsePrefix("0.0.0.0/0"),           // the default route
			netip.MustParsePrefix("128.0.0.0/1"),         // a capture route
			netip.MustParsePrefix("::/1"),
		})
	for _, direction := range []Direction{Outbound, Inbound} {
		v4 := reachableOf(filtersOf(plan.Filters(), FamilyIPv4, direction))
		v6 := reachableOf(filtersOf(plan.Filters(), FamilyIPv6, direction))
		for _, want := range []string{"203.0.113.9/32", "198.51.100.4/32", "81.2.69.0/24", "195.208.0.0/16",
			"192.168.0.0/16", "255.255.255.255/32", "224.0.0.0/4"} {
			if !slices.Contains(v4, netip.MustParsePrefix(want)) {
				t.Fatalf("IPv4 exemptions lack %s: %v", want, v4)
			}
		}
		for _, want := range []string{"2001:db8::9/128", "2a02:6b8:1:2::/64", "fe80::/10", "ff00::/8"} {
			if !slices.Contains(v6, netip.MustParsePrefix(want)) {
				t.Fatalf("IPv6 exemptions lack %s: %v", want, v6)
			}
		}
		// The default and capture routes would exempt the whole internet.
		for _, prefix := range append(v4, v6...) {
			if prefix.Bits() < 2 {
				t.Fatalf("a default or capture route was exempted: %v", prefix)
			}
			if prefix != prefix.Masked() {
				t.Fatalf("an unmasked prefix was exempted: %v", prefix)
			}
		}
		// Public addresses that nothing routes elsewhere stay guarded: those
		// are exactly where a call's media goes.
		for _, address := range []string{"142.250.82.10", "74.125.250.10", "2001:4860:4864:6::10"} {
			addr := netip.MustParseAddr(address)
			for _, prefix := range append(v4, v6...) {
				if prefix.Contains(addr) {
					t.Fatalf("%s is exempted by %s", address, prefix)
				}
			}
		}
	}
}

func TestPlanExemptsDNSAndDHCPToAnyAddress(t *testing.T) {
	// The Windows DNS client queries each interface's own servers from a
	// socket bound to that interface, and a DHCP lease is renewed the same
	// way; neither may break while the tunnel is up.
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, direction := range []Direction{Outbound, Inbound} {
			var ports []uint16
			for _, filter := range filtersOf(NewPlan(42, true, nil, nil).Filters(), family, direction) {
				if filter.Condition.Kind == ConditionRemotePorts && filter.Action == ActionPermit {
					ports = filter.Condition.Ports
				}
			}
			for _, port := range []uint16{53, 67, 547} {
				if !slices.Contains(ports, port) {
					t.Fatalf("IPv%d direction %d does not exempt port %d: %v", family, direction, port, ports)
				}
			}
		}
	}
}

func TestPlanCollapsesCoveredPrefixes(t *testing.T) {
	var routed []netip.Prefix
	// Host routes inside a /16 another route already covers.
	for i := 0; i < 300; i++ {
		routed = append(routed, netip.MustParsePrefix(fmt.Sprintf("195.208.%d.%d/32", i/256, i%256)))
	}
	routed = append(routed, netip.MustParsePrefix("195.208.0.0/16"))
	plan := NewPlan(42, false, nil, routed)
	for _, prefix := range ofFamily(plan.Reachable, FamilyIPv4) {
		if prefix.Bits() == 32 && netip.MustParsePrefix("195.208.0.0/16").Contains(prefix.Addr()) {
			t.Fatalf("%v is covered by 195.208.0.0/16 and should have been collapsed", prefix)
		}
	}
	if plan.TooManyRoutes {
		t.Fatal("a short route list was taken as too many")
	}
	for _, filter := range plan.Filters() {
		if len(filter.Condition.Prefixes) > prefixesPerFilter {
			t.Fatalf("filter %q has %d conditions", filter.Name, len(filter.Condition.Prefixes))
		}
	}
}

func TestPlanRefusesARouteListItCannotExempt(t *testing.T) {
	// Past the bound the plan is not to be installed at all: a partial list
	// would refuse destinations the routing table sends elsewhere.
	var routed []netip.Prefix
	for i := 0; i < maxRoutedPerFamily+100; i++ {
		routed = append(routed, netip.PrefixFrom(netip.AddrFrom4([4]byte{45, byte(i >> 8), byte(i), 0}), 24))
	}
	plan := NewPlan(42, false, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, routed)
	if !plan.TooManyRoutes {
		t.Fatal("an over-long route list was not refused")
	}
	// And the fixed exemptions were never at stake: the transport's server and
	// local space are in every plan, however long the route list.
	plan = NewPlan(42, false, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, routed[:maxRoutedPerFamily-10])
	if plan.TooManyRoutes {
		t.Fatal("a route list within the bound was refused")
	}
	for _, want := range append([]string{"203.0.113.9/32"}, "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32") {
		if !slices.Contains(plan.Reachable, netip.MustParsePrefix(want)) {
			t.Fatalf("%s was lost to a long route list", want)
		}
	}
}

func TestPlanSplitsTheExemptionsThatFollowTheRoutingTable(t *testing.T) {
	plan := NewPlan(42, true, nil, []netip.Prefix{netip.MustParsePrefix("195.208.0.0/16")})
	if len(plan.StaticFilters())+len(plan.ReachableFilters()) != len(plan.Filters()) {
		t.Fatal("the static and routed halves do not make up the plan")
	}
	for _, filter := range plan.StaticFilters() {
		if filter.Condition.Kind == ConditionRemotePrefixes {
			t.Fatalf("a routed exemption is among the static filters: %q", filter.Name)
		}
	}
	for _, filter := range plan.ReachableFilters() {
		if filter.Condition.Kind != ConditionRemotePrefixes || filter.Action != ActionPermit {
			t.Fatalf("the routed half holds something other than exemptions: %+v", filter)
		}
	}
}

func TestPlanKeepsExistingTCPAndMulticastReception(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		outbound := filtersOf(NewPlan(42, true, nil, nil).Filters(), family, Outbound)
		inbound := filtersOf(NewPlan(42, true, nil, nil).Filters(), family, Inbound)
		has := func(filters []Filter, kind ConditionKind) bool {
			return slices.ContainsFunc(filters, func(filter Filter) bool {
				return filter.Action == ActionPermit && filter.Condition.Kind == kind
			})
		}
		// A connection open before the tunnel came up is re-authorized when
		// the filters go in; it is left to finish, not cut.
		if !has(outbound, ConditionTCPReauthorized) {
			t.Fatalf("IPv%d does not keep existing TCP connections", family)
		}
		// An IPTV stream from an operator's public source arrives on the card.
		if !has(inbound, ConditionLocalPrefixes) {
			t.Fatalf("IPv%d does not let multicast and broadcast in", family)
		}
		if has(outbound, ConditionLocalPrefixes) {
			t.Fatalf("IPv%d exempts by local address outbound, where it would match nothing useful", family)
		}
	}
}
