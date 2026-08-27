/*
Package keyservice implements a gRPC API that can be used by SOPS to encrypt and decrypt the data key using remote
master keys.
*/
package keyservice

import (
	"encoding/json"
	"fmt"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/hckms"
	"github.com/getsops/sops/v3/hcvault"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"github.com/getsops/sops/v3/plugin"
)

// KeyFromMasterKey converts a SOPS internal MasterKey to an RPC Key that can be serialized with Protocol Buffers
func KeyFromMasterKey(mk keys.MasterKey) Key {
	switch mk := mk.(type) {
	case *pgp.MasterKey:
		return Key{
			KeyType: &Key_PgpKey{
				PgpKey: &PgpKey{
					Fingerprint: mk.Fingerprint,
				},
			},
		}
	case *gcpkms.MasterKey:
		return Key{
			KeyType: &Key_GcpKmsKey{
				GcpKmsKey: &GcpKmsKey{
					ResourceId: mk.ResourceID,
				},
			},
		}
	case *hcvault.MasterKey:
		return Key{
			KeyType: &Key_VaultKey{
				VaultKey: &VaultKey{
					VaultAddress: mk.VaultAddress,
					EnginePath:   mk.EnginePath,
					KeyName:      mk.KeyName,
				},
			},
		}
	case *kms.MasterKey:
		ctx := make(map[string]string)
		for k, v := range mk.EncryptionContext {
			ctx[k] = *v
		}
		return Key{
			KeyType: &Key_KmsKey{
				KmsKey: &KmsKey{
					Arn:        mk.Arn,
					Role:       mk.Role,
					Context:    ctx,
					AwsProfile: mk.AwsProfile,
				},
			},
		}
	case *azkv.MasterKey:
		return Key{
			KeyType: &Key_AzureKeyvaultKey{
				AzureKeyvaultKey: &AzureKeyVaultKey{
					VaultUrl: mk.VaultURL,
					Name:     mk.Name,
					Version:  mk.Version,
				},
			},
		}
	case *age.MasterKey:
		return Key{
			KeyType: &Key_AgeKey{
				AgeKey: &AgeKey{
					Recipient: mk.Recipient,
				},
			},
		}
	case *hckms.MasterKey:
		return Key{
			KeyType: &Key_HckmsKey{
				HckmsKey: &HckmsKey{
					KeyId: mk.KeyID,
				},
			},
		}
	case *plugin.MasterKey:
		// config marshal failure degrades to {}: the wire value feeds config, never path selection
		configJSON, err := json.Marshal(mk.Config)
		if err != nil {
			configJSON = []byte("{}")
		}
		return Key{
			KeyType: &Key_PluginKey{
				PluginKey: &PluginKey{
					BinaryName: mk.BinaryName,
					Config:     string(configJSON),
					KeyRef:     mk.KeyRef,
				},
			},
		}
	default:
		panic(fmt.Sprintf("Tried to convert unknown MasterKey type %T to keyservice.Key", mk))
	}
}
