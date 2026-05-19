# Cisco IS-IS Configuration

## Enable IS-IS

```
router isis <area_tag>
 net <nsap_address>
 is-type <level-1|level-2|level-1-2>
```

- `net` — Network Entity Title (NSAP address)
- `is-type` — router level type

## Enable on Interface

```
interface <interface>
 ip router isis <area_tag>
 isis circuit-type <level-1|level-2|level-1-2>
 isis priority <priority> level-2
```

- `ip router isis` — enable IS-IS on interface
- `circuit-type` — interface level type

## DIS Election

```
interface <interface>
 isis priority <priority>
```

Higher priority wins DIS election.

## Route Summarization

```
router isis
 summary-address <network> <mask> level-1-2
```

Summarize routes.

## Authentication

```
router isis
 authentication mode md5 level-1
 authentication key-chain <name> level-2
interface <interface>
 isis authentication mode md5 level-1
```

Interface and level authentication.

## Passive Interface

```
router isis
 passive-interface <interface>
```

Suppress hello on interface.

## Metric Style

```
router isis
 metric-style wide
```

Wide metrics for extended TLVs.

## Display IS-IS

```
show clns neighbors
show isis database
show isis route
show clns interface
```

## Cisco IS-IS Commands Reference

| Cisco | Huawei |
|-------|--------|
| `router isis <area>` | `isis <process_id>` + `network-entity` |
| `net <nsap>` | `network-entity <nsap>` |
| `is-type level-1` | `is-level level-1` |
| `ip router isis` | `isis enable` |
| `isis priority` | `isis priority` |
| `summary-address` | `summary` |
| `passive-interface` | `passive-interface` |
| `show clns neighbors` | `display isis peer` |
| `show isis database` | `display isis lsdb` |