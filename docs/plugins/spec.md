# The sops-plugin/1 protocol specification

Version 1. This document defines the wire protocol spoken between SOPS and
out-of-tree encryption backend plugins. It is written for a plugin author with
no prior SOPS context. The key words MUST, MUST NOT, SHOULD, and MAY are to be
interpreted as described in RFC 2119.

## 1. Overview and goals

SOPS encrypts files with a 32-byte data key; the data key itself is wrapped by
one or more master keys (KMS, age, PGP, and so on). A plugin is an executable
that wraps and unwraps that data key using a backend SOPS does not know about.
The plugin never sees the file contents, only the data key.

SOPS speaks this protocol to a plugin over its stdin and stdout: it spawns the
executable, performs a handshake, then sends one request per key operation
(wrap or unwrap the data key) and reads exactly one response per request. A
plugin can be a long-lived process that serves many requests, or a one-shot
process that answers a single request and exits cleanly; both are first-class.

Everything a plugin MUST do is in this document. A minimal conforming plugin
is roughly 100 lines of code in any language that can read lines from stdin,
write lines to stdout, and access environment credentials.

## 2. Threat model

The local machine is trusted: the PATH, HOME, and the binaries installed
there. This is the same trust class as age plugins and kubectl client
credentials, and the protocol is deliberately modeled on both. Installing a
plugin is a supply-chain decision of the same weight as installing kubectl or
an age plugin: the process runs with SOPS's privileges and sees data keys.

Repository contents are NOT trusted for executable selection. An encrypted
file in a repository, and the repository's own committed `.sops.yaml`, can
name a plugin binary, but they can never cause SOPS to execute one. This is
enforced structurally:

- Binary names are charset-checked and resolved only from PATH, never from
  the current directory (section 9).
- A `path:` override must be absolute; a relative path in a committed config
  is rejected (section 9).
- Execution is gated by an allowlist in a LOCAL config file that never ships
  in the repository (section 9). No allowlist, no execution.

The plugin process inherits SOPS's full environment. Credentials the plugin
needs (API keys, tokens) SHOULD come from the environment or from the
plugin's own protected storage, never from repository content.

One disclosure is accepted: encrypted file metadata is plaintext and reveals
binary names, key references, and plugin versions, so it discloses
infrastructure topology. This is the same exposure SOPS already has with KMS
ARNs and age recipients in metadata.

## 3. Process model

SOPS spawns one process per distinct plugin binary per key operation. The
protocol is lockstep: exactly one outstanding request at a time, so lines on
stdout can never interleave.

Respawn tolerance and the restart budget:

- A plugin MAY exit cleanly (exit status 0) after any response. Clean exits
  never count against the restart budget; SOPS respawns on the next request
  and re-runs the handshake. One-shot plugins are supported, not tolerated.
- A clean exit BEFORE any byte of a response has been written (SOPS sees EOF
  on stdout with no partial line) causes a respawn and the request is resent
  without counting.
- The following count against the restart budget, which is 3 per key
  operation: process death with garbage or partial output, timeouts, and
  response id mismatch. A request whose response line had BEGUN is never
  resent: resending could double-apply a wrapped key. The operation fails
  instead.
- A plugin that keeps exiting cleanly without answering anything does not
  hang SOPS: total spawn attempts per request are capped (at most 8), after
  which SOPS gives up with an error.

## 4. Handshake

Immediately after spawn, SOPS writes one line to the plugin's stdin:

```json
{"protocol":"sops-plugin","max_version":1}
```

The plugin answers with one line on stdout:

```json
{"protocol":"sops-plugin","version":1,"plugin":"myplugin","plugin_version":"1.2.3"}
```

Field meanings:

- `protocol`: MUST be exactly the string `sops-plugin`.
- `max_version`: the maximum protocol version SOPS supports.
- `version`: the protocol version the plugin will speak. MUST be at least 1
  and MUST NOT exceed `max_version`. As far as the version fields go, SOPS
  accepts any reply in the range 1..max_version and refuses anything
  outside it. (Separately from versioning, a handshake also fails on a
  wrong `protocol` string, an empty `plugin` name, a non-JSON or invalid
  first line, or a timeout, per sections 3 and 7.)
- `plugin`: the plugin's own name, for diagnostics. Non-empty.
- `plugin_version`: the plugin's version, semver-style (`1.2.3`, `v1.2.3`).
  SOPS records it in file metadata; `sops plugins verify` requires it to look
  like a version.

Version policy: a future version 2 will be additive only (new JSON fields,
new action names). Both sides MUST ignore unknown JSON fields. A plugin that
receives an action it does not implement MUST answer with the
`unsupported_action` error code (section 6), not exit or hang.

The handshake repeats after every respawn. Request ids restart at 1 on each
spawn. Any output on stdout before the handshake response is a protocol
violation; the first stdout line SOPS reads MUST be the handshake response.

## 5. Messages

After the handshake, SOPS sends requests, one JSON object per line:

```json
{"id":1,"action":"encrypt","config":{"key_id":"..."},"plaintext":"AAAA..."}
{"id":2,"action":"decrypt","wrapped":"myplugin.v1.AAAA..."}
```

Fields:

- `id`: integer, assigned by SOPS starting at 1 in each process. The plugin
  MUST echo it in the response. A mismatched id is a protocol violation.
- `action`: `"encrypt"` (wrap a data key) or `"decrypt"` (unwrap).
- `config`: present on encrypt requests only. An arbitrary JSON object from
  the creation rule (section 11). Opaque to SOPS, meaningful to the plugin.
- `plaintext`: present on encrypt requests only. The 32-byte data key,
  standard padded base64.
- `wrapped`: present on decrypt requests only. The opaque wrapped-key string
  the plugin previously produced.

Responses, one JSON object per line:

```json
{"id":1,"ok":true,"wrapped":"myplugin.v1.AAAA...","key_ref":"keys/primary"}
{"id":2,"ok":true,"plaintext":"AAAA..."}
{"id":3,"ok":false,"error":{"code":"key_unavailable","message":"backend unreachable"}}
```

Fields:

- `id`: MUST equal the request id.
- `ok`: true on success, false on a handled failure (section 6).
- `wrapped`: encrypt responses only. The wrapped data key (section 8). MUST
  be non-empty on a successful encrypt.
- `key_ref`: encrypt responses only, optional. A stable identifier for the
  key used (a backend key id, for example). Recorded in file metadata and
  used for rotation checks (section 11).
- `plaintext`: decrypt responses only, base64. MUST be non-empty on a
  successful decrypt and MUST be exactly the bytes that were encrypted.
- `error`: ok:false responses only, with `code` and `message` both non-empty
  (section 6).

ALL strings on the wire MUST be valid UTF-8. SOPS rejects a line that is not
valid UTF-8.

A complete encrypt exchange (handshake omitted):

```json
-> {"id":1,"action":"encrypt","config":{"key_id":"projects/p/keys/k"},"plaintext":"c2VjcmV0LWRhdGEta2V5LTI1Ni1iaXRz"}
<- {"id":1,"ok":true,"wrapped":"myplugin.v1.z7f3...","key_ref":"projects/p/keys/k"}
```

And a decrypt that fails:

```json
-> {"id":1,"action":"decrypt","wrapped":"myplugin.v1.z7f3..."}
<- {"id":1,"ok":false,"error":{"code":"auth_failed","message":"credential rejected"}}
```

## 6. Error taxonomy

Error codes are frozen for v1. A plugin MUST use one of:

| code | meaning |
|---|---|
| `invalid_request` | the request is malformed or the wrapped blob is undecodable |
| `unsupported_action` | the action is not one the plugin implements |
| `config_error` | the config object is missing required fields or malformed |
| `auth_failed` | the backend rejected the plugin's credentials |
| `key_unavailable` | the referenced backend key does not exist or is unreachable |
| `internal` | anything else; the plugin's own bug |

`ok:false` is an ANSWER, not a crash. SOPS never respawns and never retries
an answered request; the error propagates to the user immediately. An
ok:false response without a complete error object (both `code` and
`message` non-empty) is itself rejected as invalid. In
particular, `auth_failed` is fatal with no retry: retrying deterministic
credential failures against cloud KMS backends is how accounts get locked
out. A plugin that wants retries (for transient backend errors) owns that
logic itself before answering.

Exit codes (relevant only before or outside the request loop, since an
answered request never triggers exit-code inspection):

- 0: clean exit. After a complete response, this is the normal one-shot exit.
- 1: generic failure mid-protocol.
- 2: authentication or configuration failure at startup, before the
  handshake (the kubectl convention). SOPS does not parse exit codes, but a
  startup failure SHOULD exit non-zero and write the reason to stderr; SOPS
  surfaces the handshake read failure, and captured stderr accompanies
  restart-budget exhaustion errors.

## 7. Framing

- Exactly one JSON object per line, terminated by a single LF (`0x0A`).
- CRLF is forbidden: a CR byte anywhere in a line is a violation. Plugins
  MUST NOT emit CRLF, and SOPS rejects it.
- No blank lines.
- Exactly one response line per request line. No unsolicited output: stdout
  is protocol only, ever. Everything else (logging, progress, warnings)
  goes to stderr.
- The plugin MUST flush stdout after writing each response line, before
  waiting for the next request. This rule exists because of a concrete
  failure: a Python plugin using `print()` without `flush=True` writes the
  response into the interpreter's stdout buffer and SOPS hangs until the
  request timeout. Buffer your stdout, but flush every line.
- A response line that is never terminated (EOF or hang mid-line) is a
  partial-line violation; SOPS never accepts it and never resends the
  request.

Size caps, enforced by SOPS:

- Lines are capped at 1 MiB, inclusive of the LF terminator. SOPS rejects
  an oversized plugin line without buffering it whole; since config and
  wrapped values are themselves capped well below this, a request line
  from SOPS can never approach the cap. Plugins SHOULD apply the same
  1 MiB read cap defensively.
- The serialized `config` object is capped at 64 KiB (rejected when the
  creation rule is loaded, before any process spawns).
- The wrapped blob in file metadata is capped at 64 KiB (rejected when the
  encrypted file is loaded, before any process spawns).
- Captured stderr is capped at 8 KiB per process; anything beyond is
  truncated (and never blocks the plugin: SOPS discards the excess).
- Protocol-violation error messages include at most a 256-byte prefix of the
  offending stdout line, so garbage that might echo key material is never
  shown whole.

## 8. Wrapped keys

The wrapped key is opaque to SOPS: an arbitrary non-empty string up to the
64 KiB metadata cap. Two conventions are REQUIRED of plugins:

- Version prefix. The wrapped value MUST begin with a versioned prefix so a
  plugin can evolve its format and a corrupted blob is detectable. The
  convention is `<name>.v1.<payload>`, for example
  `myplugin.v1.z7f3...`, where `<name>` is the plugin's BINARY name
  (the `binary:` value in `.sops.yaml`, that is, the suffix of
  `sops-plugin-myplugin`), not the handshake `plugin` string. The
  prefix is what lets the plugin distinguish
  "foreign or corrupt blob" (`invalid_request`) from "my blob, backend
  unreachable" (`key_unavailable`).
- Base64 payload. If the wrapped value contains binary ciphertext, encode
  it as standard padded base64 in the payload section, so the value is a
  clean single-line UTF-8 string.

Decrypt must work from the wrapped blob ALONE plus environment
credentials. The decrypt request carries no config (section 5): a plugin
that needs a config file at decrypt time has a bug, because a file
decrypted by a teammate or on a CI runner has no config to offer beyond
what the environment provides.

Config MUST NOT contain credentials. The config object is transmitted
verbatim to the plugin, and, when a network key service is used with
plugins enabled, across the network to that server (section 11). Treat
config as non-secret parameters (key ids, endpoints, options).

## 9. Binary resolution and the allowlist

Discovery: for a plugin named `foo`, SOPS searches PATH for an executable
named `sops-plugin-foo` (on Windows, `sops-plugin-foo.exe`), first PATH hit
wins. The current directory is never searched on any OS, even if it appears
in PATH as an empty entry.

Windows specifics: only `.exe` is accepted. PATHEXT is not consulted, so
`.cmd`, `.bat`, and `.ps1` are refused even if they shadow an executable
further down PATH; SOPS reports the script it found so the user learns a
native executable is required. On POSIX the file must have an execute bit.

Binary name charset: `[a-zA-Z0-9_-]{1,128}`. Anything else is rejected
before resolution.

`path:` override: a creation rule MAY name an explicit path instead of a
PATH lookup. The path MUST be absolute (a relative path is rejected: a
committed config must not ship an executable location) and MUST satisfy the
same executable rules. The override never crosses the key service wire
(section 11).

The allowlist. Executing a plugin binary is gated by a LOCAL config file:
`~/.sops.yaml`, or the path in the `SOPS_LOCAL_CONFIG` environment
variable. Its shape:

```yaml
plugins:
  allowed:
    - myplugin
    - otherplugin
```

Every spawn, for encryption and decryption alike, passes this gate. No
allowlist, or an empty one, blocks every plugin: SOPS fails closed. A
missing binary on the list blocks that binary; the error states plainly
that repository content cannot grant execution. The committed repo
`.sops.yaml` is irrelevant to this gate (SOPS never reads it for the
allowlist) and a load failure of the local file is itself blocking. The
only bypass is an explicit diagnostic command where the user named the
executable on the command line (`sops plugins verify`, and the read-only
handshake probe behind `sops plugins list`).

The local config also accepts a global `plugins.timeout` (section 10).

## 10. Lifecycle and timeouts

Timeouts, in precedence order:

1. Per-key `timeout` in the creation rule (a Go duration string, e.g.
   `60s`, `2m`). Must be positive.
2. Global `plugins.timeout` in the local config (applies whenever the key
   has no timeout of its own; this is how a decrypt-timeout policy is set,
   since decrypt has no creation rule input).
3. Default: 30 seconds per request.

The timeout covers reading one response line, handshake included. On
timeout SOPS kills the plugin's whole process tree: the process group is
sent SIGKILL on POSIX (the child is spawned in its own group so a wedged
tree cannot take SOPS with it); on Windows the tree is killed via
`taskkill /T /F` with a direct process kill as backstop. A timed-out
request counts against the restart budget and is never resent (section 3).

Child hygiene: on Linux the child is spawned with Pdeathsig SIGKILL so a
killed SOPS does not orphan a key-holding process. (Known Go runtime
caveat: the kernel fires Pdeathsig when the forking thread dies, and the
runtime retires threads, so a healthy child can rarely die under load; the
respawn path self-heals this.) Other POSIX systems get the process group
only; Windows has no equivalent, so a hard-killed SOPS can leave a plugin
process behind until it notices stdin closing.

For `sops edit`, only the decrypt is a plugin key operation (the save
reuses the existing wrapped keys; master keys are not re-wrapped when
editing).

## 11. Interaction with sops

Creation rules. Plugins appear in `.sops.yaml` either at the rule level or
inside `key_groups`, like any other key type:

```yaml
creation_rules:
  - path_regex: secrets/.*$
    plugins:
      - binary: myplugin
        key_ref: projects/p/locations/eu/keys/k
        timeout: 60s
        config:
          key_id: projects/p/locations/eu/keys/k
    key_groups:
      - age:
          - age1...
        plugins:
          - binary: myplugin
            config:
              key_id: projects/p/locations/eu/keys/k
```

Fields: `binary` (required, the name used for resolution, section 9),
`path` (optional absolute override), `timeout` (optional), `key_ref`
(optional, see rotation below), `config` (the opaque object sent on encrypt
requests). The serialized config is capped at 64 KiB.

File metadata. A wrapped plugin key is stored in the encrypted file's
metadata as:

```json
"plugin": [
  {
    "binary_name": "myplugin",
    "key_ref": "projects/p/locations/eu/keys/k",
    "enc": "myplugin.v1.z7f3...",
    "created_at": "2026-01-15T10:30:00Z",
    "plugin_version": "1.2.3"
  }
]
```

Config NEVER appears in metadata. The wrapped blob (`enc`) is capped at
64 KiB at file load. `created_at` is RFC 3339.

Re-encryption. Editing an encrypted file reuses the wrapped keys already
in metadata; a key that already has a wrapped value is not re-wrapped.
Fresh config reaches a plugin only through the creation rule matched by
path, which is what `sops updatekeys` applies: it diffs the metadata keys
against the rule's key groups (a plugin key's identity is binary name
plus key reference, falling back to a digest of the serialized config
when no key reference exists). If nothing differs, the file is left
alone. If anything differs, updatekeys replaces the metadata key groups
with the rule's fresh keys and re-wraps ALL of them, common keys
included: your plugin IS invoked for a key whose identity did not
change, with the rule's config, and produces a new wrapped value; only
the key's identity is preserved, never its old wrapped blob. A file
whose path matches no creation rule fails `updatekeys` with an error,
leaving the file and its existing wrapped keys unchanged.

Rotation. `NeedsRotation` compares the key reference recorded in metadata
against the rule's `key_ref`: if they differ, sops reports the file as
needing rotation. Without a rule `key_ref`, plugin keys are never flagged.

Old-sops boundary. SOPS binaries from before this feature do not know the
plugin metadata key type: when such a binary loads and re-saves a file, it
DROPS the plugin key array from metadata. The wrapped keys become
undecryptable by everyone once the file is re-saved. Teams MUST adopt a
version floor across everyone who edits the files before mixing plugin
keys into them.

Key service. SOPS's local, in-process key service client runs plugins
(spawns still pass this machine's allowlist). A network key service
(`sops keyservice`) REFUSES plugin keys unless started with
`--enable-plugins`, since remote clients must not select server-side
executables by default. Over the wire the plugin key carries binary name,
config (verbatim JSON, opaque), and key reference; the path override and
per-key timeout do not cross the wire, and server-side spawns obey the
SERVER's allowlist. The local client wraps plugin keys in-process against
the caller's own key object (the key reference the plugin answers with
cannot cross the wire), so a plugin key wrapped by a remote key service is
written with an empty `key_ref` until the file is re-wrapped locally. (Protocol-buffer field 3 of the plugin key message is
reserved: it briefly held a wrapped value and was removed as write-only
before release.)

## 12. Conformance

Two diagnostics ship in the CLI:

- `sops plugins list` scans PATH for `sops-plugin-*` executables and prints
  one `name<TAB>version-summary<TAB>path` line per plugin, probing each
  with a handshake (3 second timeout). Read-only: no allowlist is
  consulted, nothing beyond the handshake is executed. This is the tool for
  "why does sops not find my plugin" questions (not on PATH, not
  executable, a shadowing `.cmd` file on Windows).
- `sops plugins verify <binary>` runs four positive checks against an
  explicitly named binary and prints one PASS/FAIL line per check:

  1. handshake: the version exchange succeeds and `plugin_version` is
     semver-ish;
  2. roundtrip: two distinct 32-byte probes are encrypted and decrypted
     back to exact bytes. The probes are chosen to catch cheaters: probe A
     is a ramping sequence, probe B spans the full byte range 0x00..0xFF
     (catching NUL and high-byte mangling), and decryption happens in
     encryption order, so a plugin that stores and echoes the last
     plaintext fails;
  3. error-shape: a deliberately undecryptable blob must be ANSWERED with
     ok:false and a complete error object (a wrapper that "successfully
     decrypts" garbage has no integrity);
  4. repeat: a second encrypt on the live session, then a forced respawn
     and a third encrypt, both succeed.

A verify PASS means positive protocol conformance: framing, round trip,
error object shape, and respawn tolerance. It does NOT mean cryptographic
correctness; sops cannot tell a sound cipher from ROT13. The misbehavior
matrix (garbage output, wrong ids, oversized lines, hangs) is enforced by
the SOPS-side host on every real session, not by verify: a third-party
binary cannot be made to simulate those faults on demand.

## 13. Spec changelog

- v1 (this document): initial protocol specification.
