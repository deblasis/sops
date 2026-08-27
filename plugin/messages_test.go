package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestMarshalOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(request{ID: 2, Action: "decrypt", Wrapped: "x.v1.abc"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":2,"action":"decrypt","wrapped":"x.v1.abc"}`, string(b))
}

func TestResponseUnmarshalOK(t *testing.T) {
	var r response
	require.NoError(t, json.Unmarshal([]byte(`{"id":1,"ok":true,"wrapped":"test.v1.abc","key_ref":"k/1"}`), &r))
	assert.Equal(t, int64(1), r.ID)
	assert.True(t, r.OK)
	assert.Equal(t, "test.v1.abc", r.Wrapped)
	assert.Equal(t, "k/1", r.KeyRef)
	assert.Nil(t, r.Error)
}

func TestResponseUnmarshalError(t *testing.T) {
	var r response
	require.NoError(t, json.Unmarshal([]byte(`{"id":3,"ok":false,"error":{"code":"auth_failed","message":"denied"}}`), &r))
	assert.Equal(t, int64(3), r.ID)
	assert.False(t, r.OK)
	require.NotNil(t, r.Error)
	assert.Equal(t, errCodeAuthFailed, r.Error.Code)
	assert.Equal(t, "denied", r.Error.Message)
	assert.Equal(t, "plugin error auth_failed: denied", r.Error.Error())
}

func TestPlaintextBase64RoundTrip(t *testing.T) {
	in := request{ID: 1, Action: "encrypt", Plaintext: []byte{0xde, 0xad, 0xbe, 0xef}}
	b, err := json.Marshal(in)
	require.NoError(t, err)

	var out request
	require.NoError(t, json.Unmarshal(b, &out))
	assert.Equal(t, in.Plaintext, out.Plaintext)
}
