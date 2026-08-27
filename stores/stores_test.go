package stores

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/plugin"
)

func TestValToString(t *testing.T) {
	assert.Equal(t, "1", ValToString(1))
	assert.Equal(t, "1.0", ValToString(1.0))
	assert.Equal(t, "1.1", ValToString(1.10))
	assert.Equal(t, "1.23", ValToString(1.23))
	assert.Equal(t, "1.2345678901234567", ValToString(1.234567890123456789))
	assert.Equal(t, "200000.0", ValToString(2e5))
	assert.Equal(t, "-2E+10", ValToString(-2e10))
	assert.Equal(t, "2E-10", ValToString(2e-10))
	assert.Equal(t, "1.2345E+100", ValToString(1.2345e100))
	assert.Equal(t, "1.2345E-100", ValToString(1.2345e-100))
	assert.Equal(t, "true", ValToString(true))
	assert.Equal(t, "false", ValToString(false))
	ts, _ := time.Parse(time.RFC3339, "2025-01-02T03:04:05Z")
	assert.Equal(t, "2025-01-02T03:04:05Z", ValToString(ts))
	assert.Equal(t, "a string", ValToString("a string"))
}

// wireMap runs a metadata struct through the same encode path the format
// stores use (mapstructure into a generic map), returning the wire-shaped map.
func wireMap(t *testing.T, md metadata) map[string]interface{} {
	t.Helper()
	branch, err := metadataToTreeBranch(md)
	assert.NoError(t, err)
	m, err := sopsToGoMap(branch)
	assert.NoError(t, err)
	return m
}

// metadataFromWireMap decodes a wire-shaped map through the same decode path
// the format stores use.
func metadataFromWireMap(t *testing.T, m map[string]interface{}) metadata {
	t.Helper()
	var md metadata
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &md,
		WeaklyTypedInput: true,
	})
	assert.NoError(t, err)
	assert.NoError(t, d.Decode(m))
	return md
}

func wireMapFromJSON(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	assert.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestPluginMetadataRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := sops.Metadata{
		LastModified: now,
		Version:      "3.10.0",
		KeyGroups: []sops.KeyGroup{{
			&plugin.MasterKey{
				BinaryName:    "ocikms",
				WrappedKey:    "ocikms.v1.abc",
				KeyRef:        "ocid1.key.oc1..x",
				PluginVersion: "0.1.0",
				CreationDate:  now,
			},
		}},
	}
	md := metadataFromInternal(in)
	if assert.Len(t, md.PluginKeys, 1) {
		key := md.PluginKeys[0]
		assert.Equal(t, "ocikms", key.BinaryName)
		assert.Equal(t, "ocid1.key.oc1..x", key.KeyRef)
		assert.Equal(t, "ocikms.v1.abc", key.EncryptedDataKey)
		assert.Equal(t, now.Format(time.RFC3339), key.CreatedAt)
		assert.Equal(t, "0.1.0", key.PluginVersion)
	}

	wire := wireMap(t, md)
	b, err := json.Marshal(wire)
	assert.NoError(t, err)
	assert.NotContains(t, string(b), "config")
	assert.NotContains(t, string(b), "timeout")
	assert.Contains(t, string(b), `"binary_name"`)

	md2 := metadataFromWireMap(t, wireMapFromJSON(t, b))
	out, err := md2.ToInternal()
	assert.NoError(t, err)
	if assert.Len(t, out.KeyGroups, 1) && assert.Len(t, out.KeyGroups[0], 1) {
		key, ok := out.KeyGroups[0][0].(*plugin.MasterKey)
		if assert.True(t, ok) {
			assert.Equal(t, "ocikms", key.BinaryName)
			assert.Equal(t, "ocikms.v1.abc", key.WrappedKey)
			assert.Equal(t, "ocid1.key.oc1..x", key.KeyRef)
			assert.Equal(t, "0.1.0", key.PluginVersion)
			assert.True(t, key.CreationDate.Equal(now))
		}
	}
}

func TestPluginMetadataKeyGroupsRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := sops.Metadata{
		LastModified: now,
		KeyGroups: []sops.KeyGroup{
			{
				&plugin.MasterKey{
					BinaryName:   "ocikms",
					WrappedKey:   "ocikms.v1.abc",
					KeyRef:       "ocid1.key.oc1..x",
					CreationDate: now,
				},
				&age.MasterKey{Recipient: "age1qykis35t5h7jcm8v9na7e6j8gxu0wpspca354e9dh39mkjc5xqqq69l9xz", EncryptedKey: "AGE-ENCRYPTED-FILE"},
			},
			{
				&plugin.MasterKey{
					BinaryName:    "otherkms",
					WrappedKey:    "otherkms.v1.xyz",
					KeyRef:        "other/key/ref",
					PluginVersion: "0.2.0",
					CreationDate:  now,
				},
			},
		},
	}
	md := metadataFromInternal(in)
	if assert.Len(t, md.KeyGroups, 2) {
		assert.Len(t, md.KeyGroups[0].PluginKeys, 1)
		assert.Len(t, md.KeyGroups[0].AgeKeys, 1)
		assert.Len(t, md.KeyGroups[1].PluginKeys, 1)
		assert.Empty(t, md.KeyGroups[1].AgeKeys)
	}

	wire := wireMap(t, md)
	b, err := json.Marshal(wire)
	assert.NoError(t, err)

	md2 := metadataFromWireMap(t, wireMapFromJSON(t, b))
	out, err := md2.ToInternal()
	assert.NoError(t, err)
	if assert.Len(t, out.KeyGroups, 2) {
		assert.Len(t, out.KeyGroups[0], 2)
		assert.Len(t, out.KeyGroups[1], 1)
		key, ok := out.KeyGroups[1][0].(*plugin.MasterKey)
		if assert.True(t, ok) {
			assert.Equal(t, "otherkms", key.BinaryName)
			assert.Equal(t, "otherkms.v1.xyz", key.WrappedKey)
			assert.Equal(t, "other/key/ref", key.KeyRef)
			assert.Equal(t, "0.2.0", key.PluginVersion)
		}
		var hasAge bool
		for _, k := range out.KeyGroups[0] {
			if _, ok := k.(*age.MasterKey); ok {
				hasAge = true
			}
		}
		assert.True(t, hasAge)
	}
}

func TestPluginWrappedBlobCapAtLoad(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	wire := map[string]interface{}{
		"version":      "3.10.0",
		"lastmodified": now.Format(time.RFC3339),
		"mac":          "deadbeef",
		"plugin": []interface{}{map[string]interface{}{
			"binary_name": "ocikms",
			"key_ref":     "ocid1.key.oc1..x",
			"enc":         strings.Repeat("A", 65*1024),
			"created_at":  now.Format(time.RFC3339),
		}},
	}
	md := metadataFromWireMap(t, wire)
	_, err := md.ToInternal()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "ocikms")
		assert.Contains(t, err.Error(), fmt.Sprint(maxWrappedBytes))
	}
}

func TestPluginBadCreatedAt(t *testing.T) {
	wire := map[string]interface{}{
		"version":      "3.10.0",
		"lastmodified": "2026-08-27T00:00:00Z",
		"mac":          "deadbeef",
		"plugin": []interface{}{map[string]interface{}{
			"binary_name": "ocikms",
			"enc":         "ocikms.v1.abc",
			"created_at":  "not-a-time",
		}},
	}
	md := metadataFromWireMap(t, wire)
	_, err := md.ToInternal()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "ocikms")
		assert.Contains(t, err.Error(), "created_at")
	}
}

func TestPluginMetadataLegacyNeutrality(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	wire := map[string]interface{}{
		"version":      "3.9.4",
		"lastmodified": now.Format(time.RFC3339),
		"mac":          "deadbeef",
		"age": []interface{}{map[string]interface{}{
			"recipient": "age1qykis35t5h7jcm8v9na7e6j8gxu0wpspca354e9dh39mkjc5xqqq69l9xz",
			"enc":       "AGE-ENCRYPTED-FILE",
		}},
	}
	md := metadataFromWireMap(t, wire)
	out, err := md.ToInternal()
	assert.NoError(t, err)
	if assert.Len(t, out.KeyGroups, 1) && assert.Len(t, out.KeyGroups[0], 1) {
		_, ok := out.KeyGroups[0][0].(*age.MasterKey)
		assert.True(t, ok)
	}

	re := wireMap(t, metadataFromInternal(out))
	b, err := json.Marshal(re)
	assert.NoError(t, err)
	assert.NotContains(t, string(b), `"plugin"`)
}
