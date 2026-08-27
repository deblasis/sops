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
	for _, r := range RunConformance(bin) {
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
	for _, r := range RunConformance(bin) {
		if !r.Pass {
			t.Errorf("%s: %s", r.Name, r.Detail)
		}
	}
}

func TestConformanceCatchesBrokenBinary(t *testing.T) {
	// a binary that exits immediately cannot pass conformance
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "exit1_startup")
	if !hasFail(RunConformance(bin)) {
		t.Fatal("startup-failing binary must fail conformance")
	}
}

func TestConformanceRejectsGarbageBinary(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "garbage")
	if !hasFail(RunConformance(bin)) {
		t.Fatal("garbage-emitting binary must fail conformance")
	}
}
