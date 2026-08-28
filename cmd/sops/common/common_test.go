package common

import (
	"sync"
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/plugin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type warnCaptureHook struct {
	mu      sync.Mutex
	entries []string
}

func (h *warnCaptureHook) Levels() []logrus.Level { return []logrus.Level{logrus.WarnLevel} }
func (h *warnCaptureHook) Fire(e *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, e.Message)
	return nil
}

func pluginRule() *config.Config {
	return &config.Config{
		KeyGroups: []sops.KeyGroup{
			{plugin.NewMasterKey("myplugin", nil, 0, "")},
		},
	}
}

func plainRule() *config.Config {
	return &config.Config{
		KeyGroups: []sops.KeyGroup{
			{kms.NewMasterKey("arn:aws:kms:us-east-1:1:key/x", "", nil)},
		},
	}
}

func treeWithGroups(groups []sops.KeyGroup) *sops.Tree {
	return &sops.Tree{
		FilePath: "secrets/file.yaml",
		Metadata: sops.Metadata{KeyGroups: groups},
	}
}

// rule has plugin keys, metadata does not: the old-sops re-save diagnosis
func TestWarnDroppedPluginKeysWarnsWhenMetadataLacksPluginKeys(t *testing.T) {
	hook := &warnCaptureHook{}
	logger := logrus.StandardLogger()
	prev := logger.ReplaceHooks(map[logrus.Level][]logrus.Hook{
		logrus.WarnLevel: {hook},
	})
	defer logger.ReplaceHooks(prev)

	WarnDroppedPluginKeys(pluginRule(), treeWithGroups(plainRule().KeyGroups))

	hook.mu.Lock()
	defer hook.mu.Unlock()
	require.Len(t, hook.entries, 1)
	assert.Contains(t, hook.entries[0], "secrets/file.yaml")
	assert.Contains(t, hook.entries[0], "updatekeys")
	assert.Contains(t, hook.entries[0], "plugin")
}

func TestWarnDroppedPluginKeysSilentWhenMetadataHasPluginKeys(t *testing.T) {
	hook := &warnCaptureHook{}
	logger := logrus.StandardLogger()
	prev := logger.ReplaceHooks(map[logrus.Level][]logrus.Hook{
		logrus.WarnLevel: {hook},
	})
	defer logger.ReplaceHooks(prev)

	WarnDroppedPluginKeys(pluginRule(), treeWithGroups(pluginRule().KeyGroups))

	hook.mu.Lock()
	defer hook.mu.Unlock()
	assert.Empty(t, hook.entries)
}

// no matched rule (nil conf) or a rule without plugin keys: nothing to say
func TestWarnDroppedPluginKeysSilentWithoutRuleOrPluginRule(t *testing.T) {
	hook := &warnCaptureHook{}
	logger := logrus.StandardLogger()
	prev := logger.ReplaceHooks(map[logrus.Level][]logrus.Hook{
		logrus.WarnLevel: {hook},
	})
	defer logger.ReplaceHooks(prev)

	WarnDroppedPluginKeys(nil, treeWithGroups(plainRule().KeyGroups))
	WarnDroppedPluginKeys(plainRule(), treeWithGroups(plainRule().KeyGroups))

	hook.mu.Lock()
	defer hook.mu.Unlock()
	assert.Empty(t, hook.entries)
}
