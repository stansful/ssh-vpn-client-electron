package routing

import (
	"net/netip"
	"strings"
)

type Mode string

const (
	ModeProxyAll      Mode = "proxy-all"
	ModeSelectedRules Mode = "selected-rules"
)

type RuleType string

const (
	RuleDomain      RuleType = "domain"
	RuleIP          RuleType = "ip"
	RuleProcessName RuleType = "process.name"
)

type Rule struct {
	ID        string   `json:"id"`
	Type      RuleType `json:"type"`
	Value     string   `json:"value"`
	Enabled   bool     `json:"enabled"`
	CreatedAt string   `json:"createdAt,omitempty"`
	UpdatedAt string   `json:"updatedAt,omitempty"`
}

type Descriptor struct {
	DestinationDomain string `json:"destinationDomain,omitempty"`
	DestinationIP     string `json:"destinationIp,omitempty"`
	DestinationPort   int    `json:"destinationPort,omitempty"`
	ProcessName       string `json:"processName,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
}

type Decision struct {
	ShouldProxy   bool   `json:"shouldProxy"`
	Reason        string `json:"reason"`
	RuleID        string `json:"ruleId,omitempty"`
	BlockedReason string `json:"blockedReason,omitempty"`
}

type Summary struct {
	Mode         Mode `json:"mode"`
	EnabledRules int  `json:"enabledRules"`
	DomainRules  int  `json:"domainRules"`
	IPRules      int  `json:"ipRules"`
	ProcessRules int  `json:"processRules"`
	InvalidRules int  `json:"invalidRules"`
}

type Matcher struct {
	mode      Mode
	domains   []compiledDomainRule
	ips       []compiledIPRule
	processes []compiledProcessRule
	invalid   int
}

type compiledDomainRule struct {
	id       string
	pattern  string
	wildcard bool
}

type compiledIPRule struct {
	id     string
	prefix netip.Prefix
}

type compiledProcessRule struct {
	id   string
	name string
}

func NewMatcher(mode Mode, rules []Rule) Matcher {
	matcher := Matcher{mode: mode}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		normalized := normalizeRuleValue(rule.Type, rule.Value)
		switch rule.Type {
		case RuleDomain:
			if !validDomainPattern(normalized) {
				matcher.invalid++
				continue
			}
			matcher.domains = append(matcher.domains, compiledDomainRule{
				id:       rule.ID,
				pattern:  strings.TrimPrefix(normalized, "*."),
				wildcard: strings.HasPrefix(normalized, "*."),
			})
		case RuleIP:
			prefix, ok := parseIPPrefix(normalized)
			if !ok {
				matcher.invalid++
				continue
			}
			matcher.ips = append(matcher.ips, compiledIPRule{id: rule.ID, prefix: prefix})
		case RuleProcessName:
			if !validProcessName(normalized) {
				matcher.invalid++
				continue
			}
			matcher.processes = append(matcher.processes, compiledProcessRule{id: rule.ID, name: normalized})
		default:
			matcher.invalid++
		}
	}
	return matcher
}

func validDomainPattern(value string) bool {
	domain := strings.TrimPrefix(value, "*.")
	return validDomainName(domain, true)
}

func ValidProxyDomain(value string) bool {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")
	return validDomainName(domain, false)
}

func validDomainName(domain string, requireMultipleLabels bool) bool {
	if domain == "" || len(domain) > 253 || requireMultipleLabels && !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) < 1 || len(label) > 63 || !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !isASCIIAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func validProcessName(value string) bool {
	if value == "" || len(value) > 260 || strings.ContainsAny(value, `/\\`) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlphaNumeric(character) && !strings.ContainsRune("._+- ", rune(character)) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func (m Matcher) Decide(descriptor Descriptor) Decision {
	if strings.EqualFold(descriptor.Protocol, "udp") {
		return Decision{ShouldProxy: false, Reason: "no-match", BlockedReason: "udp-not-supported"}
	}

	if m.mode == ModeProxyAll {
		return Decision{ShouldProxy: true, Reason: "proxy-all"}
	}

	if m.enabledRulesCount() == 0 {
		return Decision{ShouldProxy: false, Reason: "no-enabled-rules"}
	}

	domain := strings.ToLower(strings.TrimSpace(descriptor.DestinationDomain))
	if domain != "" {
		for _, rule := range m.domains {
			if domainMatches(rule, domain) {
				return Decision{ShouldProxy: true, Reason: "domain", RuleID: rule.id}
			}
		}
	}

	if descriptor.DestinationIP != "" {
		if ip, err := netip.ParseAddr(strings.TrimSpace(descriptor.DestinationIP)); err == nil {
			for _, rule := range m.ips {
				if rule.prefix.Contains(ip) {
					return Decision{ShouldProxy: true, Reason: "ip", RuleID: rule.id}
				}
			}
		}
	}

	processName := strings.ToLower(strings.TrimSpace(descriptor.ProcessName))
	if processName != "" {
		for _, rule := range m.processes {
			if rule.name == processName {
				return Decision{ShouldProxy: true, Reason: "process.name", RuleID: rule.id}
			}
		}
	}

	return Decision{ShouldProxy: false, Reason: "no-match"}
}

func (m Matcher) Summary() Summary {
	return Summary{
		Mode:         m.mode,
		EnabledRules: m.enabledRulesCount(),
		DomainRules:  len(m.domains),
		IPRules:      len(m.ips),
		ProcessRules: len(m.processes),
		InvalidRules: m.invalid,
	}
}

func (m Matcher) enabledRulesCount() int {
	return len(m.domains) + len(m.ips) + len(m.processes)
}

func normalizeRuleValue(ruleType RuleType, value string) string {
	trimmed := strings.TrimSpace(value)
	if ruleType == RuleDomain || ruleType == RuleProcessName {
		return strings.ToLower(trimmed)
	}
	return trimmed
}

func parseIPPrefix(value string) (netip.Prefix, bool) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	return netip.PrefixFrom(addr, 128), true
}

func domainMatches(rule compiledDomainRule, domain string) bool {
	if rule.wildcard {
		return strings.HasSuffix(domain, "."+rule.pattern) && len(domain) > len(rule.pattern)+1
	}
	return domain == rule.pattern
}
