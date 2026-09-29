# Opt-in Linux host guard

`HostKillSwitch` uses the in-process `libnftables.so.1` API and owns uniquely
named `inet` and `arp` `imperium_guard_*` tables per instance. It does not call `nft` or a shell in
the node, and it does not flush or edit existing firewall tables. The caller
must explicitly opt in and refuse startup if `install()` fails because
`libnftables`, nftables kernel support, or `CAP_NET_ADMIN` is unavailable.

Modes:

- **Armed** (initial): the guard is ready and does not block host traffic.
- **Engaged**: output and postrouting drop IPv4 and IPv6 egress unless the
  outgoing interface is loopback; the ARP output hook drops ARP too. This
  includes mesh UDP underlay, TUN traffic, DNS, and forwarded IP traffic.
  Unix control sockets remain local. Privileged raw Ethernet/packet sockets
  can bypass these families; this is not a guarantee against a hostile root
  process crafting layer-2 frames.
- **Disarmed**: the guard stops restricting traffic. Other firewall rules
  continue to apply.

The guard does not auto-engage when a link drops. Only an explicit operator
Engage should call `set_mode(HostGuardMode::Engaged)`. Report the new state only
after that call succeeds; a requested state is not kernel confirmation.

`remove()` and normal `Drop` delete only this instance's two tables. If the
process is killed or loses `CAP_NET_ADMIN` before cleanup, the tables may
persist. An Engaged stale table continues blocking egress. To recover, inspect
`sudo nft list tables` and identify the exact `imperium_guard_*` name logged at
installation, confirm its owning node is gone, then run both
`sudo nft delete table arp <exact_table_name>` and
`sudo nft delete table inet <exact_table_name>`. Do not use `flush ruleset`:
that would erase unrelated firewall policy. Recovery changes host network
state and must be an explicit operator action.

## Isolated kernel tests

The production module has no test-time dependency on a real host firewall.
The ignored acceptance test refuses to run unless it is inside a separate
network namespace and the explicit test marker is set. Run it with a dummy
egress route inside a temporary, unprivileged user/network namespace:

```sh
unshare -Urn sh -c 'ip link set lo up && ip link add dummy0 type dummy && ip addr add 198.51.100.1/24 dev dummy0 && ip -6 addr add 2001:db8:100::1/64 dev dummy0 && ip link set dummy0 up && IMPERIUM_HOST_GUARD_NS_TEST=1 cargo test --offline -p imperium-net-host --test host_guard_namespace explicit_engage_blocks_host_ipv4_ipv6_and_dns_then_cleans_up -- --ignored --nocapture'
```

That test sends IPv4 and IPv6 DNS probes and ordinary UDP toward the dummy
route, checks the kernel's nftables drop counter, checks loopback still works,
then disarms and removes its own table. The test's `nft` subprocess is only an
independent observer; the production guard sends its commands through the
libnftables API.

The permission refusal test removes `CAP_NET_ADMIN` *inside the namespace*:

```sh
unshare -Urn sh -c 'IMPERIUM_HOST_GUARD_NS_TEST=1 setpriv --bounding-set=-net_admin cargo test --offline -p imperium-net-host --test host_guard_namespace startup_refuses_when_cap_net_admin_is_unavailable -- --ignored --nocapture'
```
