package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBinaryName(t *testing.T) {
	for name, ok := range map[string]bool{
		"ocikms":      true,
		"my-plugin_2": true,
		"":            false,
		"a b":         false,
		"x/y":         false,
		"../evil":     false,
	} {
		err := validateBinaryName(name)
		if ok {
			assert.NoError(t, err, "name %q", name)
		} else {
			assert.Error(t, err, "name %q", name)
		}
	}
}

func TestResolveViaPathOnly(t *testing.T) {
	bin := buildTestPlugin(t)
	prependPath(t, filepath.Dir(bin))

	got, err := resolvePlugin("testplugin", "")
	require.NoError(t, err)
	want, err := filepath.Abs(filepath.Clean(bin))
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(want), filepath.Clean(got))
}

func TestResolveRejectsCwdPlant(t *testing.T) {
	plantDir := t.TempDir()
	name := "sops-plugin-evil"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	require.NoError(t, os.WriteFile(filepath.Join(plantDir, name), []byte("#!/bin/sh\nexit 1\n"), 0o755))

	// PATH deliberately points elsewhere: cwd must never be consulted
	prependPath(t, t.TempDir())
	t.Chdir(plantDir)

	_, err := resolvePlugin("evil", "")
	require.Error(t, err)
	assert.False(t, errors.Is(err, errNotExecutableType))
}

func TestResolveRejectsRelativeOverride(t *testing.T) {
	_, err := resolvePlugin("testplugin", "./plugins/x")
	require.Error(t, err)
	assert.ErrorContains(t, err, "absolute")
}

func TestResolveOverrideMustBeExecutable(t *testing.T) {
	_, err := resolvePlugin("testplugin", filepath.Join(t.TempDir(), "nope.exe"))
	require.Error(t, err)

	_, err = resolvePlugin("testplugin", t.TempDir())
	require.Error(t, err)
}

func TestResolveWindowsExeOnly(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sops-plugin-shimmy.cmd"), []byte("@echo off\r\n"), 0o755))
	prependPath(t, dir)

	_, err := resolvePlugin("shimmy", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errNotExecutableType)
}

func TestResolvePosixExecBitEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix-only")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sops-plugin-x"), []byte("#!/bin/sh\nexit 1\n"), 0o644))
	prependPath(t, dir)

	_, err := resolvePlugin("x", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errNotFound)
}

func TestResolveNotFoundMessage(t *testing.T) {
	// an empty dir on PATH, plus the ambient PATH, has no sops-plugin-* entries
	prependPath(t, t.TempDir())

	exe := "sops-plugin-missing"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	_, err := resolvePlugin("missing", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errNotFound)
	assert.ErrorContains(t, err, exe)
}
