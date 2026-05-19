# H3C IS-IS Configuration

## Enable IS-IS

```
isis <process_id>
 network-entity <area_id>.<system_id>.00
 is-type <level-1|level-2|level-1-2>
```

- `network-entity` — NSAP address
- `is-type` — router type

## Enable on Interface

```
interface <interface>
 isis enable <process_id>
 isis circuit-type <level-1|level-2|level-1-2>
 isis priority <priority> level-2
```

- `circuit-type` — interface level
- `priority` — DIS election

## Route Summarization

```
isis
 summary <network> <mask> level-1-2
```

Summarize routes.

## Authentication

```
isis
 authentication-mode md5 level-1
 authentication-mode simple level-2
interface <interface>
 isis authentication-mode md5 level-1
```

Level-based authentication.

## Passive Interface

```
isis
 passive-interface <interface>
```

Suppress hello on interface.

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

## H3C IS-IS Commands Reference

| Cisco | H3C |
|-------|-----|
| `router isis <area>` | `isis <process_id>` + `network-entity` |
| `net <nsap>` | `network-entity <nsap>` |
| `is-type level-1` | `is-type level-1` |
| `ip router isis` | `isis enable` |
| `isis priority` | `isis priority` |
| `summary-address` | `summary` |
| `passive-interface` | `passive-interface` |
| `show clns neighbors` | `display isis peer` |
| `show isis database` | `display isis lsdb` |