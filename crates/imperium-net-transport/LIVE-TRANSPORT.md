# Live transport profiles

`LiveTransportRuntime` controls explicit Xray and AmneziaWG backend processes.
It does not discover, install, or emulate either backend. No Xray or AmneziaWG
binary or configuration was found in the current checkout or on this host's
standard command path during implementation.

The node owner supplies a JSON array of profiles and names one initial profile.
Every path must be absolute. The launch arguments and health arguments must
contain `{config}`; the runtime replaces it with the canonical, readable config
path. The `activate`, `deactivate`, and `active_path_probe` command arguments
also require `{config}`. No shell interprets these arguments unless the operator
explicitly names a shell as the executable. The health command checks backend
readiness; the active-path probe must verify that packets actually take the
selected backend. Process liveness alone does not establish VPN health.
The profile JSON, backend configs, executables, and probe/action executables
must be owned by the current user or root and cannot be group/world writable;
unsafe parent directories are rejected. In an unprivileged user namespace,
unmapped ownership is accepted only for non-writable system binaries under
`/usr/bin` or `/bin`, never for profile JSON or backend configs.

The following is a **schema example only**. The paths and flags are deliberately
illustrative and must be replaced with values supported by the installed
backends. It contains no credentials.

```json
[
  {
    "profile_id": "xray-primary",
    "kind": "xray",
    "executable": "/ABSOLUTE/PATH/TO/INSTALLED/XRAY",
    "config": "/ABSOLUTE/PATH/TO/XRAY-CONFIG",
    "args": ["BACKEND-SUPPORTED-CONFIG-FLAG", "{config}"],
    "health_probe": {
      "executable": "/ABSOLUTE/PATH/TO/XRAY-TRAFFIC-HEALTH-CHECK",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "activate": {
      "executable": "/ABSOLUTE/PATH/TO/XRAY-PATH-ACTIVATE",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "deactivate": {
      "executable": "/ABSOLUTE/PATH/TO/XRAY-PATH-DEACTIVATE",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "active_path_probe": {
      "executable": "/ABSOLUTE/PATH/TO/VERIFY-XRAY-ROUTE",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "startup_timeout_ms": 10000,
    "graceful_stop_timeout_ms": 3000
  },
  {
    "profile_id": "amneziawg-primary",
    "kind": "amneziawg",
    "executable": "/ABSOLUTE/PATH/TO/INSTALLED/AMNEZIAWG-DAEMON",
    "config": "/ABSOLUTE/PATH/TO/AMNEZIAWG-CONFIG",
    "args": ["BACKEND-SUPPORTED-CONFIG-FLAG", "{config}"],
    "health_probe": {
      "executable": "/ABSOLUTE/PATH/TO/AMNEZIAWG-TRAFFIC-HEALTH-CHECK",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "activate": {
      "executable": "/ABSOLUTE/PATH/TO/AMNEZIAWG-PATH-ACTIVATE",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "deactivate": {
      "executable": "/ABSOLUTE/PATH/TO/AMNEZIAWG-PATH-DEACTIVATE",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "active_path_probe": {
      "executable": "/ABSOLUTE/PATH/TO/VERIFY-AMNEZIAWG-ROUTE",
      "args": ["{config}"],
      "timeout_ms": 1500
    },
    "startup_timeout_ms": 10000,
    "graceful_stop_timeout_ms": 3000
  }
]
```

`start()` launches the named initial profile, waits for backend health, runs
its activation command, and verifies the active path before reporting ready.
`set_active("xray" | "amneziawg")` starts or rechecks that backend's selected
profile, deactivates the incumbent path, activates the candidate path, and
verifies the candidate path before changing the active role. A failed switch
attempts to deactivate the candidate and restore and verify the incumbent.
The previous process remains available as standby.
`rotate_profile(None)` rotates the active backend to its next configured
profile. `rotate_profile(Some(name))` targets a named backend. Rotation requires
at least two profiles for that backend. A candidate must start and pass its
backend probe before selection changes. Rotation of the active backend also
switches and verifies the traffic path; the old child remains available as a
standby for rollback. Rotation of a standby backend leaves the active path
untouched and stops the old standby child. Failure returns an error and leaves
the incumbent selected. `status()` rechecks both active backend and path;
`shutdown()` deactivates the path and stops all managed children.

The runtime returns no configuration contents or executable arguments in its
status and transition receipts. Success means the operator-supplied backend
and active-path probes passed for a running child. A probe that only checks
its own exit code or a stale file cannot prove a working VPN route. The exact
backend and traffic boundary needs a live test with the operator's binaries
and configs.
