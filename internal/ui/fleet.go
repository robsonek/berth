package ui

import (
	"bytes"
	"context"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/robsonek/berth/internal/status"
)

// FleetSource re-collects the fleet. The TUI calls it for a refresh (drift
// false) and for a deep scan (drift true); it is the ONLY thing the view can
// trigger, and it is read-only like everything else here.
type FleetSource func(ctx context.Context, drift bool) []status.HostStatus

// fleetModel is the pure, testable state behind the fleet view — the same
// split as stepModel for the provisioning renderer.
type fleetModel struct {
	hosts   []status.HostStatus
	cursor  int
	detail  bool
	loading bool
	// gen increments on every sweep the view starts, so a slow earlier sweep
	// landing after a newer one is discarded instead of overwriting it.
	gen int
}

func newFleetModel(hosts []status.HostStatus) fleetModel {
	return fleetModel{hosts: hosts}
}

func (m fleetModel) move(delta int) fleetModel {
	m.cursor += delta
	if m.cursor < 0 {
		m.cursor = 0
	}
	if last := len(m.hosts) - 1; m.cursor > last {
		m.cursor = last
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	return m
}

func (m fleetModel) toggleDetail() fleetModel { m.detail = !m.detail; return m }

func (m fleetModel) startLoading() fleetModel { m.loading = true; m.gen++; return m }

// applyResults installs a fresh sweep and clamps the cursor: a refresh may
// return fewer hosts than the view was showing.
func (m fleetModel) applyResults(hosts []status.HostStatus) fleetModel {
	m.hosts = hosts
	m.loading = false
	return m.move(0)
}

func (m fleetModel) View() string {
	var b bytes.Buffer
	if m.loading {
		fmt.Fprintln(&b, "probing hosts…")
	}
	if m.detail && len(m.hosts) > 0 {
		writeHostDetail(&b, m.hosts[m.cursor])
	} else {
		_ = WriteFleetTable(&b, m.hosts)
	}
	fmt.Fprintln(&b, "\n↑↓ select · enter detail · r refresh · d deep drift scan · q quit")
	return b.String()
}

// writeHostDetail prints the drill-down. Every host-derived string —
// version, probe/drift errors, domains, cert modes, service names, drift
// changes, the offsite answer — goes through SanitizeCell at its print site
// (see sanitize.go); the formatted dates and berth's own literals need none.
func writeHostDetail(w *bytes.Buffer, h status.HostStatus) {
	fmt.Fprintf(w, "%s · %s\n", SanitizeCell(hostLabel(h)), SanitizeCell(h.Endpoint))
	if h.Provisioned != nil {
		fmt.Fprintf(w, "provisioned %s by berth %s\n",
			h.Provisioned.ProvisionedAt.Format("2006-01-02"), SanitizeCell(h.Provisioned.Version))
	}
	if h.Error != "" {
		fmt.Fprintf(w, "error: %s\n", SanitizeCell(h.Error))
	}
	// Partial probe failures: a reachable host that answered only some probes
	// must not read as fully healthy in the drill-down either. The offsite
	// failure is rendered once, on the OFFSITE line (see isOffsiteDuplicate).
	for _, pe := range h.ProbeErrors {
		if isOffsiteDuplicate(h, pe) {
			continue
		}
		fmt.Fprintf(w, "probe error: %s\n", SanitizeCell(pe))
	}
	fmt.Fprintln(w, "\nSITES")
	for _, s := range h.Sites {
		expiry := "no certificate"
		if s.Cert.NotAfter != nil && s.Cert.DaysLeft != nil {
			expiry = fmt.Sprintf("%s (%dd)", s.Cert.NotAfter.Format("2006-01-02"), *s.Cert.DaysLeft)
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", SanitizeCell(s.Domain), SanitizeCell(s.Cert.Mode), expiry)
	}
	fmt.Fprintln(w, "\nSERVICES")
	for _, sv := range h.Services {
		state := "down"
		if sv.Active {
			state = "up"
		}
		if !sv.Enabled {
			state += " (not enabled)"
		}
		fmt.Fprintf(w, "  %s\t%s\n", SanitizeCell(sv.Name), state)
	}
	if h.Drift != nil {
		fmt.Fprintf(w, "\nDRIFT %s\n", SanitizeCell(driftCell(h.Drift)))
		// The abort (or did-not-run) reason: for the identity abort it carries
		// the whole remedy, so the drill-down must show it, not only --json.
		if h.Drift.Error != "" {
			fmt.Fprintf(w, "  %s\n", SanitizeCell(h.Drift.Error))
		}
		for _, st := range h.Drift.Steps {
			if st.Satisfied {
				continue
			}
			fmt.Fprintf(w, "  %s: %v\n", SanitizeCell(st.Step), sanitizeAll(st.Changes))
		}
	}
	if h.Offsite != nil {
		// A repository failure is rendered explicitly: showing it as an
		// innocuous "no snapshot" hid completely failed queries.
		var when string
		switch {
		case h.Offsite.Error != "":
			when = "FAILED: " + h.Offsite.Error
		case h.Offsite.LastSnapshot != nil:
			when = ageLabel(h.HostTime.Sub(*h.Offsite.LastSnapshot)) + " · " + h.Offsite.SnapshotID
		default:
			when = "no snapshot"
		}
		fmt.Fprintf(w, "\nOFFSITE %s\n", SanitizeCell(when))
	}
}

// resultsMsg carries a completed sweep back into the event loop, tagged with
// the generation that requested it.
type resultsMsg struct {
	gen   int
	hosts []status.HostStatus
}

type fleetProgram struct {
	model fleetModel
	src   FleetSource
	ctx   context.Context
}

// Bubble Tea v2 Model interface — Init() tea.Cmd and View() tea.View, NOT the
// v1 shapes. The repo already demonstrates both at internal/ui/tui.go:130,150.
func (p fleetProgram) Init() tea.Cmd { return nil }

func (p fleetProgram) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case resultsMsg:
		// Stale-result guard: a slower earlier sweep must never overwrite a
		// newer one. Only the generation the model is waiting for is applied.
		if msg.gen != p.model.gen {
			return p, nil
		}
		p.model = p.model.applyResults(msg.hosts)
		return p, nil
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return p, tea.Quit
		case "up", "k":
			p.model = p.model.move(-1)
		case "down", "j":
			p.model = p.model.move(1)
		case "enter":
			p.model = p.model.toggleDetail()
		case "r", "d":
			if p.model.loading {
				return p, nil // one sweep at a time
			}
			deep := msg.String() == "d"
			p.model = p.model.startLoading()
			src, ctx, gen := p.src, p.ctx, p.model.gen
			return p, func() tea.Msg { return resultsMsg{gen: gen, hosts: src(ctx, deep)} }
		}
	}
	return p, nil
}

func (p fleetProgram) View() tea.View { return tea.NewView(p.model.View()) }

// RunFleetTUI renders the interactive fleet view until the operator quits and
// returns the LAST results shown. The caller derives the exit code from those,
// not from the initial sweep: after a refresh or a deep scan, the initial slice
// is stale and would report an outcome the operator never saw.
func RunFleetTUI(ctx context.Context, w io.Writer, hosts []status.HostStatus, src FleetSource) ([]status.HostStatus, error) {
	p := tea.NewProgram(fleetProgram{model: newFleetModel(hosts), src: src, ctx: ctx}, tea.WithOutput(w), tea.WithContext(ctx))
	final, err := p.Run()
	if fp, ok := final.(fleetProgram); ok {
		return fp.result(), err
	}
	return hosts, err
}

// result is the projection RunFleetTUI returns; it exists as a named method so
// a test can cover the exact path the exit code depends on.
func (p fleetProgram) result() []status.HostStatus { return p.model.hosts }
