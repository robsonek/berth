package wizard

import "fmt"

// run drives the wizard through a prompter (huh in production, fake in tests).
func run(p prompter) (Answers, error) {
	a := defaults()
	if err := p.ServerCore(&a); err != nil {
		return Answers{}, err
	}
	adv, err := p.Confirm("Configure advanced server options (fail2ban, tuning)?")
	if err != nil {
		return Answers{}, err
	}
	if adv {
		if err := p.ServerAdvanced(&a); err != nil {
			return Answers{}, err
		}
	}

	for {
		sa := SiteAnswers{SchedulerOverride: "inherit"}

		// Collect core fields, resolving HTTP/3↔nginx and validating after each
		// attempt. Server-level fields are already inline-valid, so a failure here
		// is site-local or a cross-site duplicate: re-prompt this same site.
		for {
			if err := p.SiteCore(len(a.Sites), &sa); err != nil {
				return Answers{}, err
			}
			if sa.HTTP3 && a.NginxSource == "debian" {
				sw, err := p.Confirm("HTTP/3 requires the nginx.org package; switch the server's nginx source to nginx.org?")
				if err != nil {
					return Answers{}, err
				}
				if sw {
					a.NginxSource = "nginx"
				} else {
					sa.HTTP3 = false
				}
			}
			// Shallow copy is safe here: sa has no pointer fields populated yet
			// (Queue/Daemons are filled only after this validate loop), so cand
			// shares nothing mutable with sa. If that ordering ever changes, this
			// copy would alias sa.Queue's pointer — deep-copy then.
			cand := a
			cand.Sites = append(append([]SiteAnswers(nil), a.Sites...), sa)
			if verr := cand.ToServer().Validate(); verr != nil {
				p.ShowError(verr)
				continue
			}
			break
		}

		// Optional advanced gate: scheduler override, dedicated queue, daemons.
		adv, err := p.Confirm("Configure advanced options for this site?")
		if err != nil {
			return Answers{}, err
		}
		if adv {
			if err := p.SiteScheduler(&sa); err != nil {
				return Answers{}, err
			}
			wantQueue, err := p.Confirm("Dedicated queue worker for this site?")
			if err != nil {
				return Answers{}, err
			}
			if wantQueue {
				var q QueueAnswers
				if err := p.Queue(&q); err != nil {
					return Answers{}, err
				}
				sa.Queue = &q
			}
			daemons, err := collectDaemons(p)
			if err != nil {
				return Answers{}, err
			}
			sa.Daemons = daemons
		}

		a.Sites = append(a.Sites, sa)

		// Valkey caps multi-site at 16 logical Redis DBs — whole-config state that
		// re-prompting a site cannot fix, so gate the "add another?" offer.
		if a.Valkey && len(a.Sites) >= 16 {
			p.ShowError(fmt.Errorf("valkey caps multi-site at 16 sites (one Redis logical DB each); stopping at 16"))
			break
		}
		more, err := p.Confirm("Add another site?")
		if err != nil {
			return Answers{}, err
		}
		if !more {
			break
		}
	}
	return a, nil
}

// collectDaemons runs the "add another daemon?" sub-loop.
func collectDaemons(p prompter) ([]DaemonAnswers, error) {
	add, err := p.Confirm("Add a long-running daemon (Horizon/Reverb/custom)?")
	if err != nil {
		return nil, err
	}
	var out []DaemonAnswers
	for add {
		var d DaemonAnswers
		if err := p.Daemon(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
		add, err = p.Confirm("Add another daemon?")
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
