// Package sandbox runs commands inside locked-down, ephemeral Docker
// containers so that code from an untrusted source archive never touches
// the host directly.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// sandboxUser matches the non-root user baked into the sandbox image.
const sandboxUser = "65532:65532"

// Mount describes a host directory bind-mounted into the container.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// RunOpts configures a single sandboxed container run. Hardening flags
// (no new privileges, all capabilities dropped, read-only root filesystem,
// resource limits, non-root user) are applied unconditionally by Run —
// callers choose the image, command, mounts, and network access, nothing
// else.
type RunOpts struct {
	Image   string
	Command []string
	Mounts  []Mount
	Network bool // false gets the container --network none
}

// Available reports whether Docker is installed and its daemon is reachable.
func Available(ctx context.Context) error {
	// check that docker is in PATH and the daemon is reachable
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}
	// check that the docker daemon is reachable
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		return fmt.Errorf("docker daemon not reachable: %w", err)
	}
	return nil
}

// EnsureImage builds the sandbox image from dockerfilePath if it isn't
// already present locally, using buildContext as the build context dir.
func EnsureImage(ctx context.Context, tag, dockerfilePath, buildContext string) error {
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", tag).Run(); err == nil {
		return nil // already built
	}

	// build the image
	build := exec.CommandContext(ctx, "docker", "build", "-t", tag, "-f", dockerfilePath, buildContext)
	var out bytes.Buffer
	build.Stdout = &out
	build.Stderr = &out
	if err := build.Run(); err != nil {
		return fmt.Errorf("building sandbox image %s: %w\noutput:\n%s", tag, err, out.String())
	}
	return nil
}

// buildRunArgs turns RunOpts into the `docker run` argument list, applying
// the hardening flags unconditionally. Kept separate from Run so the
// argument-construction logic can be unit tested without invoking Docker.
func buildRunArgs(opts RunOpts) []string {
	args := []string{
		"run", "--rm",
		"--read-only",
		"--tmpfs", "/tmp",
		"--memory", "512m",
		"--pids-limit", "256",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", sandboxUser,
	}

	if opts.Network {
		args = append(args, "--network", "bridge")
	} else {
		args = append(args, "--network", "none")
	}

	for _, m := range opts.Mounts {
		spec := m.HostPath + ":" + m.ContainerPath
		if m.ReadOnly {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
	}

	args = append(args, opts.Image)
	args = append(args, opts.Command...)

	return args
}

// Run executes opts.Command inside a hardened, ephemeral container and
// returns its combined stdout/stderr.
func Run(ctx context.Context, opts RunOpts) ([]byte, error) {
	args := buildRunArgs(opts)

	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("docker run failed: %w\noutput:\n%s", err, out.String())
	}
	return out.Bytes(), nil
}
