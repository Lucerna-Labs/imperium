# Input/output capture setup revision 2 — frozen 2026-10-01

The traffic matrix, world hash, paired node configurations, case payload IDs,
counts, metrics and zero-capture-loss requirements in
`LIGHTCONE-VM-IO-PRECOMMIT-2026-10-01.md` remain unchanged.

Two setup attempts are preserved:

- `20261001-094907`: healthy and quarantined arms both delivered 49/49 probes.
  Healthy receipts matched 933 captured hashes/directions. Blocking showed
  5 hub ingress, 0 egress, and no receiver data. Recovery delivered 3 echoes,
  but the hub's buffered reader exited with 0 captured versus 12 filter-received
  packets; the recovery capture acceptance failed. This is a logging failure,
  not evidence of Lightcone blocking.
- `20261001-095519`: immediate capture and a 1.2-second pre-stop drain avoided
  that exit race, but the hub healthy capture reported 42 kernel drops under
  the 4 MiB reader buffer. The matrix stopped before the quarantined arm;
  it is not an accepted complete comparison.

Mechanically justified resource repair: retain full snaplen, immediate mode,
and the drain, but raise each capture buffer from 4 MiB to 64 MiB. Immediate
Linux packet capture has finite frame slots and a full-snaplen reader can
exhaust capacity under bursts. The larger buffer supplies bounded additional
capacity within each 3 GiB guest; three 64 MiB buffers total 192 MiB. The
actual kernel drop counters, complete case IDs and receipt/capture hash joins
must still pass; no loss threshold is relaxed and no count is corrected away.

Authorize one complete matched pair plus the same blocking/recovery control
under this revised setup. Keep all prior data and stop only owned VMs. If this
configuration still loses capture data, preserve the failure and freeze any
further resource/mechanism revision before executing it. No geometry training,
world/seal change or production host network operation is part of this repair.
