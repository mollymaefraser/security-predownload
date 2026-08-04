package sandbox

import (
	"slices"
	"testing"
)

func TestBuildRunArgs_HardeningFlagsAlwaysPresent(t *testing.T) {
	// the hardening flags should always be present in the run args, regardless of other options.
	args := buildRunArgs(RunOpts{Image: "img", Command: []string{"do-thing"}})

	// check that the hardening flags are present in the args.
	required := [][]string{
		{"--read-only"},
		{"--tmpfs", "/tmp"},
		{"--memory", "512m"},
		{"--pids-limit", "256"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--user", sandboxUser},
	}
	for _, flag := range required {
		if !containsSubsequence(args, flag) {
			t.Errorf("expected args to contain %v, got %v", flag, args)
		}
	}
}

func TestBuildRunArgs_Network(t *testing.T) {
	// the network option should be correctly reflected in the run args.
	cases := []struct {
		name    string
		network bool
		want    []string
	}{
		{"disabled by default", false, []string{"--network", "none"}},
		{"enabled when requested", true, []string{"--network", "bridge"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := buildRunArgs(RunOpts{Image: "img", Network: tc.network})
			if !containsSubsequence(args, tc.want) {
				t.Errorf("expected args to contain %v, got %v", tc.want, args)
			}
		})
	}
}

func TestBuildRunArgs_Mounts(t *testing.T) {
	// mounts should be correctly reflected in the run args.
	args := buildRunArgs(RunOpts{
		Image: "img",
		Mounts: []Mount{
			{HostPath: "/host/ro", ContainerPath: "/scan", ReadOnly: true},
			{HostPath: "/host/rw", ContainerPath: "/out", ReadOnly: false},
		},
	})

	// check that the mounts are present in the args with the correct read-only/read-write flags.
	if !containsSubsequence(args, []string{"-v", "/host/ro:/scan:ro"}) {
		t.Errorf("expected read-only mount spec, got %v", args)
	}
	if !containsSubsequence(args, []string{"-v", "/host/rw:/out"}) {
		t.Errorf("expected read-write mount spec, got %v", args)
	}
	// A read-write mount must not accidentally end up with a ":ro" suffix.
	for i, a := range args {
		if a == "/host/rw:/out:ro" {
			t.Errorf("read-write mount got a ro suffix at args[%d]: %v", i, args)
		}
	}
}

func TestBuildRunArgs_ImageAndCommandComeLast(t *testing.T) {
	// the image and command should always be the last elements in the run args.
	args := buildRunArgs(RunOpts{
		Image:   "vulnscan-sandbox:latest",
		Command: []string{"/scan/archive.tar.gz", "--no-sca"},
	})

	// check that the last three elements of args are the image and command.
	last := args[len(args)-3:]
	want := []string{"vulnscan-sandbox:latest", "/scan/archive.tar.gz", "--no-sca"}
	if !slices.Equal(last, want) {
		t.Errorf("got trailing args %v, want %v", last, want)
	}
}

// containsSubsequence reports whether want appears as a contiguous
// subsequence of got.
func containsSubsequence(got, want []string) bool {
	if len(want) == 0 || len(want) > len(got) {
		return false
	}
	for i := 0; i+len(want) <= len(got); i++ {
		if slices.Equal(got[i:i+len(want)], want) {
			return true
		}
	}
	return false
}
