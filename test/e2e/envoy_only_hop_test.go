// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build e2e

package e2e

import (
	"net"
	"os"
	"testing"
	"time"
)

// Environment contract for the Envoy-only-hop assertion. These name the
// network addresses, as seen from the mount-facing network the test-runner sits
// on, of the filestore (and the other edge-backend peers) that MUST NOT be
// directly reachable, and the edge that MUST be. The harness exports them on the
// runner; unset values skip the relevant arm so a host build stays green.
const (
	// envFilestoreAddr is the filestore host:port. From the mount-facing network
	// it must NOT be dialable: the filestore lives only on the edge-backend
	// network, so the guest has no L3 route to it.
	envFilestoreAddr = "OCU_E2E_FILESTORE_ADDR"
	// envControlPlaneAddr and envExchangeAddr name the other edge-backend peers,
	// which must likewise be unreachable from the mount-facing network.
	envControlPlaneAddr = "OCU_E2E_CONTROL_PLANE_ADDR"
	envExchangeAddr     = "OCU_E2E_EXCHANGE_ADDR"
	// envEdgeAddr is the edge host:port the guest dials. From the mount-facing
	// network it MUST be reachable — it is the only storage hop.
	envEdgeAddr = "OCU_E2E_EDGE_ADDR"
)

// dialTimeout bounds each TCP dial. Unreachability must surface as a failed
// dial within this window, not a hang.
const dialTimeout = 5 * time.Second

// TestEnvoyOnlyHop positively asserts the network-topology invariant that the
// edge is the ONLY storage hop reachable from the guest network: the filestore
// (and the other edge-backend peers) are NOT directly dialable from the
// mount-facing network, while the edge IS. This is load-bearing — the network
// topology relaxes the old network_mode:none guarantee, so confidentiality now
// rests on TLS-at-edge + the filestore's scope-validation + this single-hop
// property. The guard must BITE: if the filestore becomes directly dialable
// from the mount network this test goes red.
func TestEnvoyOnlyHop(t *testing.T) {
	if os.Getenv(envGate) == "" {
		t.Skipf("%s not set — the Envoy-only-hop assertion runs only against the live "+
			"network graph (compose run test-runner); skips clean on a host build", envGate)
	}

	// NEGATIVE arm: each edge-backend peer must be UNREACHABLE from the
	// mount-facing network. A successful dial means the topology leaked a direct
	// route to a backend the guest must only reach through the edge.
	negatives := map[string]string{
		envFilestoreAddr:    os.Getenv(envFilestoreAddr),
		envControlPlaneAddr: os.Getenv(envControlPlaneAddr),
		envExchangeAddr:     os.Getenv(envExchangeAddr),
	}
	checkedNegative := false
	for name, addr := range negatives {
		if addr == "" {
			continue
		}
		checkedNegative = true
		t.Run("unreachable_"+name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, dialTimeout)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("%s (%q) is directly dialable from the mount-facing network; the "+
					"filestore and its backend peers must be reachable ONLY through the edge "+
					"(the single-hop invariant). The two-network topology must keep them off "+
					"the mount-facing network.", name, addr)
			}
			t.Logf("%s (%q) is correctly unreachable from the mount network: %v", name, addr, err)
		})
	}

	// The filestore address is mandatory under the live gate: it is the
	// load-bearing negative. Without it the assertion would silently prove
	// nothing.
	if !checkedNegative || negatives[envFilestoreAddr] == "" {
		t.Fatalf("%s is required under the live gate (%s): the Envoy-only-hop assertion "+
			"must prove the filestore is unreachable from the mount network", envFilestoreAddr, envGate)
	}

	// POSITIVE arm: the edge MUST be reachable — it is the path the guest's
	// service_url dials. (The real file ops through the mount, which traverse
	// guest -> edge -> filestore, are proven by TestE2EExercise; this makes the
	// single hop explicit.)
	edgeAddr := os.Getenv(envEdgeAddr)
	if edgeAddr == "" {
		t.Fatalf("%s is required under the live gate (%s): the positive arm must prove "+
			"the edge — the sole storage hop — IS reachable from the mount network",
			envEdgeAddr, envGate)
	}
	t.Run("reachable_"+envEdgeAddr, func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", edgeAddr, dialTimeout)
		if err != nil {
			t.Fatalf("the edge %q is NOT reachable from the mount-facing network: %v — the "+
				"edge must be the reachable single hop", edgeAddr, err)
		}
		_ = conn.Close()
		t.Logf("the edge %q is reachable from the mount network (the single storage hop)", edgeAddr)
	})
}
