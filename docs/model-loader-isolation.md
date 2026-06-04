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

## How it works

- The server process performs the B1 gate in the **trusted parent** (it has the
  database + filesystem access needed to audit to `model_file_scan_log`).
- Only an **already-validated absolute path** is handed to the worker.
- The worker (`server/services/model-worker.js`, forked by
  `server/services/model-worker-host.js`) loads the model and runs inference in
  its **own process**. It holds the least privilege it can: no database access,
  and it reads only the model path it is given.
- One shared worker hosts both the chat model and the embedding model.

What process separation buys you inside a single container:

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

What process separation does **not** buy you on its own: inside a single
container the worker shares the container's user, Linux capabilities, and network
namespace with the server. Network-egress denial and capability dropping are
therefore applied at the **container** level (below), which transitively confines
the worker. Giving the worker a *different, lower-privileged identity* than the
server requires either an in-process privilege drop (not done today) or a
separate sidecar container (see "Stronger isolation", below).

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `FIREALIVE_MODEL_WORKER_TIMEOUT_MS` | Per-request inference timeout; on timeout the worker is killed and the request fails closed | `120000` |
| `FIREALIVE_LLM_IDLE_UNLOAD_MS` | Idle timeout after which the chat model is unloaded from the worker (frees memory) | `300000` |
| `FIREALIVE_EMBED_IDLE_UNLOAD_MS` | Idle timeout for the embedding model | `300000` |
| `FIREALIVE_ALLOW_ROOT_MODEL_LOAD` | Set to `1` to permit loading as root in production (not recommended) | unset |
| `FIREALIVE_MODEL_PATH` | Chat model directory (or `.gguf` path) — mount **read-only** | `~/.firealive/models` |
| `FIREALIVE_EMBED_MODEL_PATH` | Embedding model `.gguf` path — mount **read-only** | `<model root>/nomic-embed-text-v1.5.f16.gguf` |

The worker's restart cap (5 spawns) and window (60 s) are built-in defaults in
`model-worker-host.js`.

## Container hardening (Linux / Docker)

The base image already runs as the non-root `firealive` user. Add a
`docker-compose.override.yml` next to the shipped `docker-compose.yml` to confine
the container (and therefore the worker). Tune the limits to your model size — a
14B q4_K_M chat model needs several GB of RAM resident.

```yaml
# docker-compose.override.yml — confines the firealive container (parent + worker)
services:
  firealive:
    # Read-only root filesystem; only the data volume + a small tmpfs are writable.
    read_only: true
    tmpfs:
      - /tmp:size=256m
    volumes:
      # Models are provisioned out-of-band and mounted READ-ONLY (TOCTOU defence:
      # the file cannot change between the gate and the worker's load).
      - /srv/firealive/models:/home/firealive/.firealive/models:ro
    environment:
      - FIREALIVE_MODEL_PATH=/home/firealive/.firealive/models
      - FIREALIVE_MODEL_WORKER_TIMEOUT_MS=120000
    # Drop all Linux capabilities; the worker needs none.
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
      # Docker's default seccomp profile already blocks dangerous syscalls; keep it.
      # For a custom profile: - seccomp:/srv/firealive/seccomp-firealive.json
    # Resource bounds — a runaway/exploited worker cannot exhaust the host.
    mem_limit: 12g          # >= resident model size + headroom
    pids_limit: 256
    cpus: "4.0"
    ulimits:
      nofile: 4096
```

Network egress: the inference service never needs outbound network (models are
provisioned out-of-band, FireAlive never downloads them). Deny egress at the
network layer — e.g. attach the container to an `internal: true` Docker network,
or enforce egress rules in your orchestrator/host firewall. Do **not** rely on the
application to self-restrict the network.

Read-only model mount is the recommended complement to the worker's TOCTOU
re-stat check: with the mount read-only, the validated file cannot be swapped
between the gate and the load.

## macOS / Windows

Process isolation, crash containment, timeouts, and refuse-as-root apply on all
platforms. The capability/seccomp/network confinement above is Linux/container
specific. On macOS and Windows:

- **macOS** — rely on process isolation; an optional `sandbox-exec` profile can
  further restrict the worker. Enforcement is weaker than a hardened Linux
  container; document your posture honestly.
- **Windows** — use a Job Object to cap memory/CPU, and AppContainer where
  feasible.

## Stronger isolation (future work)

Running the worker as a **separate, lower-privileged identity** than the server
is not done in the single-container model. The stronger setups, deferred:

- A **sidecar container** for the worker with its own (more restricted) user,
  capabilities, and a no-egress network — the server talks to it over a local
  socket. This gives true per-worker identity + network confinement.
- An **in-process privilege drop** in the worker after fork.

Until then, harden the whole container as above; the worker is confined
transitively, and the gate remains the primary control.

## Honest limits

- The gate, not isolation, is what makes a model file trustworthy. Isolation
  contains the *residual* risk that a malformed file slips past validation.
- A backdoored-but-well-formed weights file is caught by none of these layers —
  hash-pinning to a vetted source is the defence there.
- `--max-old-space-size` bounds the V8 heap but has limited effect on the native
  allocations `node-llama-cpp` makes; the `mem_limit` cgroup is the real bound.
