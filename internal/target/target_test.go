package target

import "testing"

func TestExpandCIDR(t *testing.T) {
	hosts, err := Expand(
		[]string{"192.0.2.0/30"},
		100,
	)

	if err != nil {
		t.Fatal(err)
	}

	if len(hosts) != 2 {
		t.Fatalf(
			"expected 2 usable hosts, got %d",
			len(hosts),
		)
	}

	if hosts[0] != "192.0.2.1" {
		t.Fatalf(
			"expected 192.0.2.1, got %s",
			hosts[0],
		)
	}

	if hosts[1] != "192.0.2.2" {
		t.Fatalf(
			"expected 192.0.2.2, got %s",
			hosts[1],
		)
	}
}

func TestExpandMultiple(t *testing.T) {
	hosts, err := Expand(
		[]string{
			"192.0.2.10,192.0.2.11",
			"192.0.2.10",
		},
		100,
	)

	if err != nil {
		t.Fatal(err)
	}

	if len(hosts) != 2 {
		t.Fatalf(
			"expected deduplicated 2 hosts, got %d",
			len(hosts),
		)
	}
}

func TestExpansionLimit(t *testing.T) {
	_, err := Expand(
		[]string{"10.0.0.0/24"},
		10,
	)

	if err == nil {
		t.Fatal(
			"expected host expansion limit error",
		)
	}
}
