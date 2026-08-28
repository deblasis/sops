package plugin

import "testing"

func hasFail(results []ConformanceResult) bool {
	for _, r := range results {
		if !r.Pass {
			return true
		}
	}
	return false
}

func TestConformanceGreenOnTestPlugin(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	for _, r := range RunConformance(bin, nil) {
		if !r.Pass {
			t.Errorf("%s: %s", r.Name, r.Detail)
		}
	}
}

func TestConformanceToleratesOneShotPlugin(t *testing.T) {
	// a plugin that exits cleanly after every answer must still pass:
	// each request respawns, clean exits never count against the budget
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "oneshot")
	for _, r := range RunConformance(bin, nil) {
		if !r.Pass {
			t.Errorf("%s: %s", r.Name, r.Detail)
		}
	}
}

func TestConformanceConfigRequiringPlugin(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "requireconfig")

	// no config: every encrypt is answered config_error, so verify fails
	if !hasFail(RunConformance(bin, nil)) {
		t.Fatal("config-requiring plugin must fail verify without config")
	}

	// with config: the same binary must pass end to end
	for _, r := range RunConformance(bin, map[string]any{"key_id": "projects/p/keys/k"}) {
		if r.Name == "roundtrip" {
			if !r.Pass {
				t.Fatalf("roundtrip: %s", r.Detail)
			}
		}
	}
}

func TestConformanceCatchesStatefulEcho(t *testing.T) {
	// echo mode answers every decrypt with the LAST encrypted plaintext:
	// the cross-probe decrypt of A after encrypting B must fail
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "echo")
	for _, r := range RunConformance(bin, nil) {
		if r.Name == "roundtrip" {
			if r.Pass {
				t.Fatal("stateful-echo plugin must fail the roundtrip check")
			}
			return
		}
	}
	t.Fatal("no roundtrip result returned")
}

func TestConformanceCatchesBrokenBinary(t *testing.T) {
	// a binary that exits immediately cannot pass conformance
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "exit1_startup")
	if !hasFail(RunConformance(bin, nil)) {
		t.Fatal("startup-failing binary must fail conformance")
	}
}

func TestConformanceRejectsGarbageBinary(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "garbage")
	if !hasFail(RunConformance(bin, nil)) {
		t.Fatal("garbage-emitting binary must fail conformance")
	}
}
