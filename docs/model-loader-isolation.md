# Model Loader Isolation & Deployment Hardening

FireAlive runs local GGUF models with `node-llama-cpp`, which **parses the model
file and runs inference in-process**. The B1 integrity & safety gate (hash-pin →
optional signature → GGUF format validation → local malware scan → audit) is the
primary control against a malicious or malformed model file. This document covers
the **containment** layer that sits behind the gate: the model is loaded and run
in a **separate worker process**, and the deployment is hardened so that a
loader/parser exploit is trapped rather than given the run of the host.

This is defence-in-depth. Two independent controls must fail — the validator must
miss a malformed file **and** the attacker must escape the confinement — for a
compromise to reach the host.

FireAlive is deployed as a hardware-sealed application, not a container: the
Tier-1 KEK is sealed to the host TPM 2.0 / Secure Enclave and the server fails
closed without a hardware root of trust, so the deployment substrate is
bare-metal or a (v)TPM-backed VM. The hardening guidance below is therefore
process/`systemd`-based, not container-based.

## How it works

- The server process performs the B1 gate in the **trusted parent** (it has the
  database + filesystem access needed to audit to `model_file_scan_log`).
- Only an **already-validated absolute path** is handed to the worker.
- The worker (`server/services/model-worker.js`, forked by
  `server/services/model-worker-host.js`) loads the model and runs inference in
  its **own process**. It holds the least privilege it can: no database access,
  and it reads only the model path it is given.
- One shared worker hosts both the chat model and the embedding model.

What process separation buys you:

- **Crash containment** — a native fault in the loader kills only the worker; the
  host detects the exit and respawns it. The server keeps running.
- **Memory isolation** — the worker has its own address space; an out-of-bounds
  read/write is contained to the worker.
- **Timeouts + restart circuit** — a request that exceeds
  `FIREALIVE_MODEL_WORKER_TIMEOUT_MS` causes the worker to be killed and the
  request to fail closed; repeated rapid crashes trip a restart circuit that
  reports the model as unavailable instead of thrashing.
- **Refuse-as-root** — both the parent and the worker refuse to load a model as
  root in production (override with `FIREALIVE_ALLOW_ROOT_MODEL_LOAD=1` only if a
  constrained environment genuinely requires it).

What process separation does **not** buy you on its own: the forked worker
inherits the server process's user, Linux capabilities, and network access.
Network-egress denial and capability dropping are therefore applied at the
**host / service-manager** level (below), which confines the server and its
forked worker together. Giving the worker a *different, lower-privileged
identity* than the server requires either an in-process privilege drop (not done
today) or running the worker as a separate service under its own user (see
"Stronger isolation", below).

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `FIREALIVE_MODEL_WORKER_TIMEOUT_MS` | Per-request inference timeout; on timeout the worker is killed and the request fails closed | `120000` |
| `FIREALIVE_LLM_IDLE_UNLOAD_MS` | Idle timeout after which the chat model is unloaded from the worker (frees memory) | `300000` |
| `FIREALIVE_EMBED_IDLE_UNLOAD_MS` | Idle timeout for the embedding model | `300000` |
| `FIREALIVE_ALLOW_ROOT_MODEL_LOAD` | Set to `1` to permit loading as root in production (not recommended) | unset |
| `FIREALIVE_MODEL_PATH` | Chat model directory (or `.gguf` path) — keep on a **read-only** path | `~/.firealive/models` |
| `FIREALIVE_EMBED_MODEL_PATH` | Embedding model `.gguf` path — keep on a **read-only** path | `<model root>/nomic-embed-text-v1.5.f16.gguf` |

The worker's restart cap (5 spawns) and window (60 s) are built-in defaults in
`model-worker-host.js`.

## Process hardening (Linux / systemd)

Run the server (and therefore the forked worker) under a dedicated non-root
service account and a `systemd` unit that strips privilege, caps resources, and
denies network egress. Tune the memory bound to your model size — a 14B q4_K_M
chat model needs several GB of RAM resident.

```ini
# /etc/systemd/system/firealive.service -- confines the server + forked worker
[Service]
User=firealive
Group=firealive
ExecStart=/opt/firealive/bin/firealive-server
Environment=NODE_ENV=production
Environment=FIREALIVE_MODEL_PATH=/srv/firealive/models

# Filesystem: read-only OS, private /tmp, no access to other users' homes.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# The data root is the ONE writable path; the model directory stays read-only
# (TOCTOU defence: the validated file cannot change between the gate and load).
ReadWritePaths=/var/lib/firealive
ReadOnlyPaths=/srv/firealive/models

# Privilege: no escalation, drop every Linux capability (the worker needs none),
# restrict syscalls to a sane baseline, and forbid new privileges.
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false   # node-llama-cpp JITs; leave false or inference breaks

# Resource bounds -- a runaway/exploited worker cannot exhaust the host.
MemoryMax=12G          # >= resident model size + headroom
TasksMax=256
LimitNOFILE=4096
CPUQuota=400%

# Network egress: the inference service never needs outbound network (models are
# provisioned out-of-band; FireAlive never downloads them). Deny all IP traffic
# except loopback, which the embedded server needs for the MC/AC to reach it.
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
```

Do **not** rely on the application to self-restrict the network — the deny rule
belongs at the service-manager or host-firewall layer. `MemoryDenyWriteExecute`
is deliberately left off: `node-llama-cpp` allocates executable pages for its
native inference kernels and will crash under a W^X policy.

Keep the model directory read-only (a `ReadOnlyPaths=` entry, a read-only bind
mount, or filesystem permissions). This is the recommended complement to the
worker's TOCTOU re-stat check: the validated file cannot be swapped between the
gate and the load.

## macOS / Windows

Process isolation, crash containment, timeouts, and refuse-as-root apply on all
platforms. The capability/syscall/network confinement above is Linux/`systemd`
specific. On macOS and Windows:

- **macOS** — rely on process isolation; an optional `sandbox-exec` profile can
  further restrict the worker, and the app runs under the launching operator's
  account. Enforcement is weaker than a hardened Linux service; document your
  posture honestly.
- **Windows** — use a Job Object to cap memory/CPU, run the service under a
  dedicated low-privilege account, and use a host-firewall outbound rule to deny
  the process egress. AppContainer where feasible.

## Stronger isolation (future work)

Running the worker as a **separate, lower-privileged identity** than the server
is not done today. The stronger setups, deferred:

- Run the worker as its **own `systemd` service under a distinct, more
  restricted user** with its own capability/egress policy; the server talks to
  it over a local socket. This gives true per-worker identity + network
  confinement.
- An **in-process privilege drop** in the worker after fork.

Until then, harden the server service as above; the forked worker is confined
with it, and the gate remains the primary control.

## Honest limits

- The gate, not isolation, is what makes a model file trustworthy. Isolation
  contains the *residual* risk that a malformed file slips past validation.
- A backdoored-but-well-formed weights file is caught by none of these layers —
  hash-pinning to a vetted source is the defence there.
- `--max-old-space-size` bounds the V8 heap but has limited effect on the native
  allocations `node-llama-cpp` makes; the `MemoryMax=` cgroup bound is the real
  limit.
