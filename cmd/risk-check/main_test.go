package main

import (
	"context"
	"testing"
)

func TestRootCmd_ArgValidation(t *testing.T) {
	cases := [][]string{
		{},
		{"owner"},
		{"owner", "pkg", "extra"},
	}

	for _, args := range cases {
		cmd := newRootCmd(func(context.Context, string, string, bool) {})
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs(args)

		if err := cmd.Execute(); err == nil {
			t.Errorf("args %v: expected error, got nil", args)
		}
	}
}

func TestRootCmd_CallsAssessRisk(t *testing.T) {
	var gotOwner, gotPackageName string
	var gotNoScan bool
	called := false

	assessRisk := func(ctx context.Context, owner, packageName string, skipScan bool) {
		called = true
		gotOwner = owner
		gotPackageName = packageName
		gotNoScan = skipScan
	}

	cmd := newRootCmd(assessRisk)
	cmd.SetArgs([]string{"anthropics", "claude-code", "--no-scan"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected assessRisk to be called")
	}
	if gotOwner != "anthropics" {
		t.Errorf("owner = %q, want %q", gotOwner, "anthropics")
	}
	if gotPackageName != "claude-code" {
		t.Errorf("packageName = %q, want %q", gotPackageName, "claude-code")
	}
	if !gotNoScan {
		t.Error("expected noScan to be true")
	}
}

func TestRootCmd_NoScanDefaultsFalse(t *testing.T) {
	var gotNoScan bool

	cmd := newRootCmd(func(ctx context.Context, owner, packageName string, skipScan bool) {
		gotNoScan = skipScan
	})
	cmd.SetArgs([]string{"anthropics", "claude-code"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotNoScan {
		t.Error("expected noScan to default to false")
	}
}
