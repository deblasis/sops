package keyservice

import (
	"errors"

	"golang.org/x/net/context"

	"google.golang.org/grpc"

	"github.com/getsops/sops/v3/plugin"
)

// LocalClient is a key service client that performs all operations locally
type LocalClient struct {
	Server KeyServiceServer
}

// NewLocalClient creates a new local client
func NewLocalClient() LocalClient {
	// plugins enabled: the local client is in-process, not remote executable
	// selection, and spawns still pass this machine's own allowlist
	return LocalClient{Server: Server{EnablePlugins: true}}
}

// NewCustomLocalClient creates a new local client with a non-default backing
// KeyServiceServer implementation
func NewCustomLocalClient(server KeyServiceServer) LocalClient {
	return LocalClient{Server: server}
}

// InProcess reports whether svc executes in this process and hands back that
// client. Callers use it to special-case the local path (plugin key wraps run
// in-process) without asserting the concrete type themselves.
func InProcess(svc KeyServiceClient) (*LocalClient, bool) {
	lc, ok := svc.(LocalClient)
	if !ok {
		return nil, false
	}
	return &lc, true
}

// Decrypt processes a decrypt request locally
// See keyservice/server.go for more details
func (c LocalClient) Decrypt(ctx context.Context,
	req *DecryptRequest, opts ...grpc.CallOption) (*DecryptResponse, error) {
	return c.Server.Decrypt(ctx, req)
}

// Encrypt processes an encrypt request locally
// See keyservice/server.go for more details
func (c LocalClient) Encrypt(ctx context.Context,
	req *EncryptRequest, opts ...grpc.CallOption) (*EncryptResponse, error) {
	return c.Server.Encrypt(ctx, req)
}

// pluginsEnabled reports whether the backing server is the stock Server with
// plugins on
func (c LocalClient) pluginsEnabled() bool {
	s, ok := c.Server.(Server)
	return ok && s.EnablePlugins
}

// errLocalPluginsDisabled is the in-process counterpart of the server gate:
// the wire path's --enable-plugins advice is meaningless for a local client
var errLocalPluginsDisabled = errors.New("plugin keys are disabled on this key service")

// EncryptMasterKey wraps dataKey with a plugin MasterKey in-process, on the
// caller's own key object. The plugin's answer (wrapped key, key_ref, plugin
// version) must land in file metadata, and it cannot cross the keyservice
// wire, so local plugin wraps run against the original key instead of a
// server-side reconstruction.
func (c LocalClient) EncryptMasterKey(mk *plugin.MasterKey, dataKey []byte) error {
	if !c.pluginsEnabled() {
		return errLocalPluginsDisabled
	}
	return mk.Encrypt(dataKey)
}

// DecryptMasterKey is the decrypt counterpart of EncryptMasterKey: same
// in-process spawn either way, but symmetry keeps plugin keys off the wire
// on the local path entirely.
func (c LocalClient) DecryptMasterKey(mk *plugin.MasterKey) ([]byte, error) {
	if !c.pluginsEnabled() {
		return nil, errLocalPluginsDisabled
	}
	return mk.Decrypt()
}
