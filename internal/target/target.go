package target

import (
	"fmt"
	"net/netip"
	"strings"
)

func Expand(
	inputs []string,
	maxHosts int,
) ([]string, error) {
	if maxHosts <= 0 {
		maxHosts = 4096
	}

	seen := make(map[string]bool)

	var result []string

	add := func(host string) error {
		if seen[host] {
			return nil
		}

		if len(result) >= maxHosts {
			return fmt.Errorf(
				"target expansion exceeds maximum of %d hosts",
				maxHosts,
			)
		}

		seen[host] = true
		result = append(result, host)

		return nil
	}

	for _, input := range inputs {
		for _, raw := range strings.Split(input, ",") {
			token := strings.TrimSpace(raw)

			if token == "" {
				continue
			}

			if !strings.Contains(token, "/") {
				if addr, err := netip.ParseAddr(token); err == nil {
					token = addr.String()
				}

				if err := add(token); err != nil {
					return nil, err
				}

				continue
			}

			prefix, err := netip.ParsePrefix(token)
			if err != nil {
				return nil, fmt.Errorf(
					"invalid target %q: %w",
					token,
					err,
				)
			}

			prefix = prefix.Masked()

			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf(
					"IPv6 CIDR expansion is not supported in v0.5.0: %s",
					token,
				)
			}

			var expanded []string

			for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {

				expanded = append(
					expanded,
					addr.String(),
				)

				if len(result)+len(expanded) > maxHosts+2 {
					return nil, fmt.Errorf(
						"target expansion exceeds maximum of %d hosts",
						maxHosts,
					)
				}
			}

			if prefix.Bits() <= 30 && len(expanded) >= 2 {
				expanded = expanded[1 : len(expanded)-1]
			}

			for _, host := range expanded {
				if err := add(host); err != nil {
					return nil, err
				}
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf(
			"no valid targets supplied",
		)
	}

	return result, nil
}
