# Huawei IS-IS Configuration

## Enable IS-IS

```
isis <process_id>
 network-entity <area_id>.<system_id>.00
 is-level <level-1|level-2|level-1-2>
```

- `network-entity` — NSAP address format
- `is-level` — router type (L1, L2, or both)

## Enable on Interface

```
interface <interface>
 isis enable <process_id>
 isis circuit-type <level-1|level-2|level-1-2>
 isis priority <priority> level-2
```

- `circuit-type` — interface level type
- `priority` — DIS election priority

## Route Summarization

```
isis
 summary <network> <mask> level-1-2
```

Summarize routes at level boundaries.

## IS-IS Authentication

```
interface <interface>
 isis authentication-mode simple <password> level-1
 isis authentication-mode md5 <key> level-2
```

Interface-level authentication.

## Passive Interface

```
isis
 passive-interface <interface>
```

Suppress hello packets on interface.

## Metric Style

```
isis
 cost-style wide
```

Wide metrics for extended TLVs.

## Display IS-IS

```
display isis peer
display isis lsdb
display isis route
```

## Huawei IS-IS Commands Reference

| Cisco | Huawei |
|-------|--------|
| `router isis <area>` | `isis <process_id>` + `network-entity` |
| `net <nsap>` | `network-entity <nsap>` |
| `is-type level-1` | `is-level level-1` |
| `ip router isis` | `isis enable` on interface |
| `isis priority <pri>` | `isis priority <pri>` |
| `summary-address <net>` | `summary <net> <mask>` |
| `passive-interface` | `passive-interface` |
| `show clns neighbors` | `display isis peer` |
| `show isis database` | `display isis lsdb` |