# Alert context schema

`schema_version: "1.2"`

Returned by `ThreatClassificationSystem.inspect_traffic_flow(flow: dict)`. The
object is JSON-serialisable with no custom encoder.

## Top level

| Field            | Type            | Notes                                                   |
| ---------------- | --------------- | ------------------------------------------------------- |
| `schema_version` | `str`           | Bump when any field below changes shape.                |
| `timestamp_utc`  | `str`           | ISO 8601, timezone-aware, generated at inference time.  |
| `tier1`          | `object`        | Always present.                                         |
| `tier2`          | `object \| null`| `null` when Tier 1 returns `Normal`.                    |
| `mitre`          | `object \| null`| `null` when Tier 1 returns `Normal`.                    |
| `severity`       | `str`           | `INFO` `LOW` `MEDIUM` `HIGH` `CRITICAL`                 |
| `action`         | `str`           | `ALLOW` `ALERT` `BLOCK`                                 |

## `tier1`

| Field        | Type    | Notes                                              |
| ------------ | ------- | -------------------------------------------------- |
| `verdict`    | `str`   | `Normal` or `Anomalous`.                           |
| `confidence` | `float` | Probability of the predicted class, 6 dp.          |

## `tier2`

| Field                 | Type               | Notes                                            |
| --------------------- | ------------------ | ------------------------------------------------ |
| `threat_category`     | `str`              | Label from the trained encoder.                  |
| `confidence`          | `float`            | Probability of the predicted class, 6 dp.        |
| `class_probabilities` | `dict[str, float]` | Every class in `meta.json`, 6 dp. Sums to ~1.0.  |

## `mitre`

| Field            | Type  | Notes                                               |
| ---------------- | ----- | --------------------------------------------------- |
| `technique_id`   | `str` | e.g. `T1498`, or `AML.T0043` for the ATLAS fallback.|
| `technique_name` | `str` | Human-readable technique name.                      |
| `tactic`         | `str` | ATT&CK tactic, or `ATLAS — ML Attack`.              |

## Derivation rules

`severity` comes from `tier2.confidence`:

```
confidence >= 0.90  ->  CRITICAL
confidence >= 0.70  ->  HIGH
confidence >= 0.50  ->  MEDIUM
otherwise           ->  LOW
```

`action` is `BLOCK` for `CRITICAL` and `HIGH`, otherwise `ALERT`. A `Normal`
verdict is always `INFO` / `ALLOW`.

## UI guidance

- Treat `class_probabilities` as the source for confidence bars; do not
  recompute from `confidence`.
- Filter the `"Label"` key out of `class_probabilities` — it is a training
  artifact, not a real threat class. See the known limitations in the README.
- `action` is a recommendation from this module. Enforcement belongs to the
  response engine, not here.
