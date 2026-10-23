// Package egress owns the combined egress-policy state: WARP mode plus the
// vpngate home-broadband exit (OpenVPN runner model), their persistence
// (egress.json) and the health-check loop that switches nodes when the exit
// degrades.
//
// Modes (Warp × Vpngate):
//
//	warp off    + vg off    → direct (plain node, unchanged behavior)
//	warp v6     + vg off    → v6 via WARP, v4 direct (existing behavior)
//	warp off    + vg all    → v4 user traffic via the OpenVPN tunnel
//	warp v6     + vg all    → v4 via tunnel, v6 via WARP (valid combo)
//	warp all    + anything  → invalid: WARP would swallow the tunnel exit
package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/vpngate"
)

// VpngateMode selects how the vpngate residential outbound participates.
type VpngateMode string

const (
	VpngateOff VpngateMode = "off"
	VpngateAll VpngateMode = "all" // all v4 egress via the residential exit
)

// State is the persisted egress policy. It lives in egress.json inside the
// config dir and is mutated by the admin panel (and only there — env/config
// seeds the initial state but the file wins after first write).
type State struct {
	WarpMode string `json:"warp_mode"` // off | all | v6
	// Vpngate selects the residential-exit participation.
	Vpngate VpngateMode `json:"vpngate"`
	// VpngateSource holds the server-list URL and filters.
	VpngateSource vpngate.Source `json:"vpngate_source"`
	// PinnedNode optionally pins a specific volunteer node (host:port).
	// Empty = automatic (first healthy candidate).
	PinnedNode string `json:"pinned_node,omitempty"`
	// Admin holds the generated panel credentials (path + password hash).
	Admin AdminState `json:"admin"`
	// UpdatedAt is the last write time (informational).
	UpdatedAt time.Time `json:"updated_at"`
}

// AdminState is the generated control-panel auth material.
type AdminState struct {
	// BasePath is the secret URL prefix (e.g. "/x7f2a…/"); requests outside
	// it get a 404. Empty on first boot until the panel is initialized.
	BasePath string `json:"base_path,omitempty"`
	// PasswordHash is "salt:hash" hex; empty until first boot generates one.
	PasswordHash string `json:"password_hash,omitempty"`
}

// Validate returns an error for impossible combinations.
func (s *State) Validate() error {
	switch s.WarpMode {
	case "", "off", "all", "v6":
	default:
		return fmt.Errorf("warp_mode must be off/all/v6, got %q", s.WarpMode)
	}
	switch s.Vpngate {
	case VpngateOff, VpngateAll:
	default:
		return fmt.Errorf("vpngate must be off/all, got %q", s.Vpngate)
	}
	if s.WarpMode == "all" && s.Vpngate == VpngateAll {
		return errors.New("warp.mode=all cannot be combined with vpngate=all: WARP would swallow the tunnel exit; use warp v6 + vpngate all instead")
	}
	if s.Vpngate == VpngateAll {
		if strings.TrimSpace(s.VpngateSource.URL) == "" {
			return errors.New("vpngate source url is empty")
		}
	}
	return nil
}

// WarpEnabled reports whether the WARP endpoint must be generated.
func (s *State) WarpEnabled() bool { return s.WarpMode == "all" || s.WarpMode == "v6" }

// VpngateEnabled reports whether the residential exit must run.
func (s *State) VpngateEnabled() bool { return s.Vpngate == VpngateAll }

// Store persists State at <dir>/egress.json with atomic rename.
type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(dir string) *Store {
	return &Store{path: filepath.Join(dir, "egress.json")}
}

// Path exposes the backing file (admin panel display).
func (s *Store) Path() string { return s.path }

// Dir returns the directory holding the state file.
func (s *Store) Dir() string { return filepath.Dir(s.path) }

func (s *Store) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	return st, nil
}

func (s *Store) Save(st *State) error {
	st.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Exists reports whether any state file is present.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}
