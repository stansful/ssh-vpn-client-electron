//go:build windows && (amd64 || arm64)

package winfirewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Guard is an installed plan. Its filters exist for as long as its WFP session
// is open: closing it, or the process ending for any reason, removes them.
type Guard struct {
	mu          sync.Mutex
	session     uintptr
	subLayerKey windows.GUID
	tunnelLUID  uint64
	// reachable are the IDs of the filters that follow the routing table.
	reachable []uint64
	closed    bool
	closeErr  error
}

// errGuardClosed is returned by an update after Close.
var errGuardClosed = errors.New("the guard is closed")

// errTooManyRoutes refuses a plan whose exemptions do not fit.
var errTooManyRoutes = errors.New("the routing table sends more networks elsewhere than the guard can exempt")

// Start installs plan in a dynamic WFP session, all of it or none of it.
func Start(plan Plan) (*Guard, error) {
	if plan.TooManyRoutes {
		return nil, errTooManyRoutes
	}
	name, err := windows.UTF16PtrFromString("Shadow SSH tunnel")
	if err != nil {
		return nil, err
	}
	sessionInfo := fwpmSession0{
		displayData:          fwpmDisplayData0{name: name, description: name},
		flags:                fwpmSessionFlagDynamic,
		txnWaitTimeoutInMSec: sessionTransactionWaitMillis,
	}
	guard := &Guard{tunnelLUID: plan.TunnelLUID}
	if err := fwpmEngineOpen0(&sessionInfo, &guard.session); err != nil {
		return nil, fmt.Errorf("open the filtering engine: %w", err)
	}
	if err := guard.install(plan); err != nil {
		_ = fwpmEngineClose0(guard.session)
		return nil, err
	}
	return guard, nil
}

// UpdateReachable replaces the exemptions that follow the routing table with
// plan's, in one transaction: there is no moment with neither set in place.
func (g *Guard) UpdateReachable(plan Plan) error {
	if plan.TooManyRoutes {
		return errTooManyRoutes
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errGuardClosed
	}
	return g.transaction(func() error {
		added, err := g.addFilters(plan.ReachableFilters(), nil)
		if err != nil {
			return err
		}
		for _, id := range g.reachable {
			if err := fwpmFilterDeleteById0(g.session, id); err != nil {
				return fmt.Errorf("remove a previous exemption: %w", err)
			}
		}
		g.reachable = added
		return nil
	})
}

// Close removes the filters.
func (g *Guard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		g.closeErr = fwpmEngineClose0(g.session)
	}
	return g.closeErr
}

func (g *Guard) install(plan Plan) error {
	return g.transaction(func() error {
		subLayerKey, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		name, err := windows.UTF16PtrFromString("Shadow SSH tunnel: traffic stays in the tunnel adapter")
		if err != nil {
			return err
		}
		subLayer := fwpmSublayer0{
			subLayerKey: subLayerKey,
			displayData: fwpmDisplayData0{name: name, description: name},
			// The highest weight: this sublayer is evaluated first. It only
			// decides for itself - a block in any other sublayer still wins.
			weight: ^uint16(0),
		}
		if err := fwpmSubLayerAdd0(g.session, &subLayer); err != nil {
			return fmt.Errorf("add the filtering sublayer: %w", err)
		}
		g.subLayerKey = subLayerKey

		appID, err := helperAppID()
		if err != nil {
			return err
		}
		defer fwpmFreeMemory0(&appID)
		if _, err := g.addFilters(plan.StaticFilters(), appID); err != nil {
			return err
		}
		reachable, err := g.addFilters(plan.ReachableFilters(), nil)
		if err != nil {
			return err
		}
		g.reachable = reachable
		return nil
	})
}

// transaction runs operation inside a WFP transaction, committing it only if
// operation succeeds.
func (g *Guard) transaction(operation func() error) (err error) {
	if err := fwpmTransactionBegin0(g.session); err != nil {
		return fmt.Errorf("begin a filtering transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = fwpmTransactionAbort0(g.session)
		}
	}()
	if err := operation(); err != nil {
		return err
	}
	if err := fwpmTransactionCommit0(g.session); err != nil {
		return fmt.Errorf("commit the filtering transaction: %w", err)
	}
	return nil
}

func (g *Guard) addFilters(filters []Filter, appID *fwpByteBlob) ([]uint64, error) {
	ids := make([]uint64, 0, len(filters))
	for _, filter := range filters {
		id, err := g.addFilter(filter, appID)
		if err != nil {
			return nil, fmt.Errorf("add filter %q: %w", filter.Name, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// helperAppID is the WFP application identity of this executable, which the
// filters exempt: the dataplane's own direct traffic leaves by the network
// card on purpose.
func helperAppID() (*fwpByteBlob, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate this executable: %w", err)
	}
	path, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	var appID *fwpByteBlob
	if err := fwpmGetAppIdFromFileName0(path, &appID); err != nil {
		return nil, fmt.Errorf("resolve the application identity of %s: %w", executable, err)
	}
	return appID, nil
}

func (g *Guard) addFilter(filter Filter, appID *fwpByteBlob) (uint64, error) {
	name, err := windows.UTF16PtrFromString("Shadow SSH tunnel: " + filter.Name)
	if err != nil {
		return 0, err
	}
	// The conditions point at values by address, through uintptr fields the
	// garbage collector does not follow. Everything they point at is kept in
	// referents until Windows has copied the filter.
	var referents []any
	conditions, err := conditionsOf(filter, g.tunnelLUID, appID, &referents)
	if err != nil {
		return 0, err
	}
	action := fwpActionType(fwpActionPermit)
	if filter.Action == ActionBlock {
		action = fwpActionBlock
	}
	wfpFilter := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: name, description: name},
		layerKey:            layerOf(filter),
		subLayerKey:         g.subLayerKey,
		weight:              fwpValue0{kind: fwpUint8, value: uintptr(filter.Weight)},
		numFilterConditions: uint32(len(conditions)),
		action:              fwpmAction0{kind: action},
	}
	if len(conditions) > 0 {
		wfpFilter.filterCondition = &conditions[0]
	}
	var id uint64
	err = fwpmFilterAdd0(g.session, &wfpFilter, &id)
	runtime.KeepAlive(referents)
	runtime.KeepAlive(conditions)
	return id, err
}

func layerOf(filter Filter) windows.GUID {
	switch {
	case filter.Family == FamilyIPv6 && filter.Direction == Inbound:
		return layerALEAuthRecvAcceptV6
	case filter.Family == FamilyIPv6:
		return layerALEAuthConnectV6
	case filter.Direction == Inbound:
		return layerALEAuthRecvAcceptV4
	default:
		return layerALEAuthConnectV4
	}
}

// servicesDescriptor grants FWP_ACTRL_MATCH_FILTER - access right 0x1, which
// SDDL spells "CC" - to SYSTEM, LocalService and NetworkService: an
// ALE_USER_ID condition with it matches any process whose token holds one of
// them.
const servicesDescriptor = "D:(A;;CC;;;SY)(A;;CC;;;LS)(A;;CC;;;NS)"

// conditionsOf spells one filter's condition the way WFP takes it. Several
// conditions on the same field are alternatives; this is how one filter
// covers a list of prefixes or ports. Conditions on different fields must all
// hold.
func conditionsOf(filter Filter, tunnelLUID uint64, appID *fwpByteBlob, referents *[]any) ([]fwpmFilterCondition0, error) {
	condition := filter.Condition
	switch condition.Kind {
	case ConditionHelper:
		if appID == nil {
			return nil, errors.New("the helper's application identity is not known")
		}
		return []fwpmFilterCondition0{{
			fieldKey:       conditionALEAppID,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{kind: fwpByteBlobType, value: uintptr(unsafe.Pointer(appID))},
		}}, nil
	case ConditionServices:
		descriptor, err := windows.SecurityDescriptorFromString(servicesDescriptor)
		if err != nil {
			return nil, fmt.Errorf("build the services security descriptor: %w", err)
		}
		blob := &fwpByteBlob{size: descriptor.Length(), data: (*uint8)(unsafe.Pointer(descriptor))}
		*referents = append(*referents, descriptor, blob)
		return []fwpmFilterCondition0{{
			fieldKey:       conditionALEUserID,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{kind: fwpSecurityDescriptorType, value: uintptr(unsafe.Pointer(blob))},
		}}, nil
	case ConditionLoopback:
		return []fwpmFilterCondition0{flagsCondition(fwpConditionFlagIsLoopback)}, nil
	case ConditionTunnel:
		luid := new(uint64)
		*luid = tunnelLUID
		*referents = append(*referents, luid)
		return []fwpmFilterCondition0{{
			fieldKey:       conditionIPLocalInterface,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{kind: fwpUint64, value: uintptr(unsafe.Pointer(luid))},
		}}, nil
	case ConditionUDP:
		return []fwpmFilterCondition0{protocolCondition(ipProtoUDP)}, nil
	case ConditionTCP:
		return []fwpmFilterCondition0{protocolCondition(ipProtoTCP)}, nil
	case ConditionTCPReauthorized:
		return []fwpmFilterCondition0{protocolCondition(ipProtoTCP), flagsCondition(fwpConditionFlagIsReauthorize)}, nil
	case ConditionRemotePorts:
		conditions := make([]fwpmFilterCondition0, 0, len(condition.Ports))
		for _, port := range condition.Ports {
			conditions = append(conditions, fwpmFilterCondition0{
				fieldKey:       conditionIPRemotePort,
				matchType:      fwpMatchEqual,
				conditionValue: fwpValue0{kind: fwpUint16, value: uintptr(port)},
			})
		}
		return conditions, nil
	case ConditionRemotePrefixes:
		return prefixConditions(conditionIPRemoteAddress, condition.Prefixes, referents), nil
	case ConditionLocalPrefixes:
		return prefixConditions(conditionIPLocalAddress, condition.Prefixes, referents), nil
	default:
		return nil, fmt.Errorf("unknown condition kind %d", condition.Kind)
	}
}

func protocolCondition(protocol uintptr) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:       conditionIPProtocol,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{kind: fwpUint8, value: protocol},
	}
}

func flagsCondition(flags uintptr) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:       conditionFlags,
		matchType:      fwpMatchFlagsAllSet,
		conditionValue: fwpValue0{kind: fwpUint32, value: flags},
	}
}

func prefixConditions(field windows.GUID, prefixes []netip.Prefix, referents *[]any) []fwpmFilterCondition0 {
	conditions := make([]fwpmFilterCondition0, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		address := prefix.Addr().Unmap()
		if address.Is4() {
			octets := address.As4()
			value := &fwpV4AddrAndMask{addr: binary.BigEndian.Uint32(octets[:]), mask: v4Mask(prefix.Bits())}
			*referents = append(*referents, value)
			conditions = append(conditions, fwpmFilterCondition0{
				fieldKey:       field,
				matchType:      fwpMatchEqual,
				conditionValue: fwpValue0{kind: fwpV4AddrMaskType, value: uintptr(unsafe.Pointer(value))},
			})
			continue
		}
		value := &fwpV6AddrAndMask{addr: address.As16(), prefixLength: uint8(prefix.Bits())}
		*referents = append(*referents, value)
		conditions = append(conditions, fwpmFilterCondition0{
			fieldKey:       field,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{kind: fwpV6AddrMaskType, value: uintptr(unsafe.Pointer(value))},
		})
	}
	return conditions
}

func v4Mask(bits int) uint32 {
	if bits <= 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}
