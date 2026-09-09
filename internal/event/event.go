package event

import (
	"time"

	"github.com/abyssalsec/absl-recon/internal/model"
)

type Type string

const (
	PortScanned  Type = "port_scanned"
	ServiceFound Type = "service_found"
	FindingFound Type = "finding_found"
)

type Event struct {
	Type    Type
	Target  string
	Port    int
	Service model.Service
	Finding model.Finding
	At      time.Time
}
