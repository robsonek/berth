package cmd

import "testing"

func TestSubcommandsRegistered(t *testing.T) {
	root := newRootCmd()
	want := map[string]bool{"init": false, "provision": false, "site": false}
	for _, c := range root.Commands() {
		want[c.Name()] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func TestProvisionRequiresServerArg(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"provision"})
	if err := root.Execute(); err == nil {
		t.Error("expected error when provision is called without a server argument")
	}
}
