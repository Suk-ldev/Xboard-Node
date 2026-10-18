package vpngate

import "sync"

// Egress is the resolved vpngate selection handed to the kernel builders.
// It carries the active link plus the UUID to present at the entry.
type Egress struct {
	mu   sync.Mutex
	link *Link
	uuid string
}

func NewEgress(uuid string) *Egress { return &Egress{uuid: uuid} }

// Set atomically swaps the active link (health loop / admin panel).
func (e *Egress) Set(l Link) {
	e.mu.Lock()
	defer e.mu.Unlock()
	clone := l
	e.link = &clone
}

// Link returns the active link (nil when none selected yet).
func (e *Egress) Link() *Link {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.link == nil {
		return nil
	}
	clone := *e.link
	return &clone
}

// UUID returns the entry UUID override ("" = RealUUID).
func (e *Egress) UUID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.uuid
}

// ProbePort is the loopback port of the internal health-probe SOCKS inbound.
// Fixed (not config) because it must never collide with node listen ports,
// which are panel-controlled and can be anything; 64500-65500 is reserved by
// convention here and validated against the panel port in validateNodeRuntime.
const ProbePort = 64510
