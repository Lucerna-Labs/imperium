# VM packet input/output comparison

| Arm | Case | Attempts | Hub in | Hub out | Receiver data IDs | Echoes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| healthy | tunnel_udp4 | 10 | 10 | 10 | 10 | 10 |
| healthy | tunnel_tcp4 | 5 | 5 | 5 | 5 | 5 |
| healthy | tunnel_icmp4 | 3 | 3 | 3 | None | 3 |
| healthy | direct_udp4 | 10 | 10 | 10 | 10 | 10 |
| healthy | direct_udp6 | 10 | 10 | 10 | 10 | 10 |
| healthy | direct_tcp6 | 5 | 5 | 5 | 5 | 5 |
| healthy | loopback_udp4 | 3 | 3 | 0 | 3 | 3 |
| healthy | loopback_udp6 | 3 | 3 | 0 | 3 | 3 |
| quarantined | tunnel_udp4 | 10 | 10 | 10 | 10 | 10 |
| quarantined | tunnel_tcp4 | 5 | 5 | 5 | 5 | 5 |
| quarantined | tunnel_icmp4 | 3 | 3 | 3 | None | 3 |
| quarantined | direct_udp4 | 10 | 10 | 10 | 10 | 10 |
| quarantined | direct_udp6 | 10 | 10 | 10 | 10 | 10 |
| quarantined | direct_tcp6 | 5 | 5 | 5 | 5 | 5 |
| quarantined | loopback_udp4 | 3 | 3 | 0 | 3 | 3 |
| quarantined | loopback_udp6 | 3 | 3 | 0 | 3 | 3 |
| kernel_blocked | blocked_udp4 | 5 | 5 | 0 | 0 | 0 |
| kernel_recovered | recovered_udp4 | 3 | 3 | 3 | 3 | 3 |

Healthy baseline complete: True
Measurement blocking/recovery control passed: True
Delivery change detected between healthy and quarantined Lightcone: False

Bounded synthetic VM traffic, receipt availability and current forwarding dependency only; no trained-world benefit or all-host protection claim
