package vpngate

import "sync"

// Egress is the resolved vpngate selection handed to the service. With the
// OpenVPN runner model the kernel no longer consumes it (the kernel keeps a
// plain direct/final route); the health loop and admin panel do.
type Egress struct {
	mu   sync.Mutex
	row  *Row
	uuid string // unused in ovpn mode; kept for state compatibility
}

func NewEgress(uuid string) *Egress { return &Egress{uuid: uuid} }

// Set atomically swaps the active row (health loop / admin panel).
func (e *Egress) Set(r Row) {
	e.mu.Lock()
	defer e.mu.Unlock()
	clone := r
	e.row = &clone
}

// Row returns the active row copy (nil when none selected yet).
func (e *Egress) Row() *Row {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.row == nil {
		return nil
	}
	clone := *e.row
	return &clone
}

// UUID returns the stored UUID override ("" = default; unused in ovpn mode).
func (e *Egress) UUID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.uuid
}
