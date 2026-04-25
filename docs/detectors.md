# Configuring detectors

eyeexam ships with five SIEM/EDR detector backends. Configure the ones
your environment uses in `config.yaml` under `detectors:`. Multiple
detectors can claim the same expectation — a hit from any of them makes
the expectation `caught`.

| backend     | type    | expectation fields supported                       |
|-------------|---------|----------------------------------------------------|
| Loki        | `loki`  | `query` (LogQL), optional `backend: loki`          |
| Slither     | `slither` | `sigma_id`, `tag`, `query`                       |
| Wazuh       | `wazuh` | `sigma_id` (rule.id), `tag` (rule.mitre.tactic), `query` |
| Elastic     | `elastic` | `sigma_id` (rule.uuid), `tag`, `query`           |
| Splunk      | `splunk` | `sigma_id`, `tag`, `query` (raw SPL fragment)     |

Backend-specific expectation routing: setting `backend: <name>` on an
expectation restricts it to that detector. With no `backend` set, every
detector that recognises the fields will claim it.

## Loki

```yaml
detectors:
  - name: loki
    type: loki
    url: http://loki.lab:3100
    tenant: homelab               # X-Scope-OrgID header
```

## Slither (M3 stub — see docs/slither-detector.md)

```yaml
detectors:
  - name: slither
    type: slither
    url: https://slither.lab:7443
    api_key_env: EYEEXAM_SLITHER_KEY
```

## Wazuh

Wazuh's indexer is OpenSearch — eyeexam queries it directly rather than
through the Wazuh manager. Field names default to Wazuh conventions and
can be overridden if your detection pipeline normalises elsewhere.

```yaml
detectors:
  - name: wazuh
    type: wazuh
    url: https://wazuh-indexer.lab:9200
    index_pattern: wazuh-alerts-*
    username: admin
    password_env: EYEEXAM_WAZUH_PASSWORD
    # Optional field overrides:
    host_field: agent.name
    rule_field: rule.id
    tag_field:  rule.mitre.tactic
    timestamp_field: "@timestamp"
    insecure_tls: false
```

## Elastic / Elastic Security

```yaml
detectors:
  - name: elastic
    type: elastic
    url: https://es.lab:9200
    index_pattern: filebeat-*       # or .alerts-security.alerts-*
    api_key_env: EYEEXAM_ELASTIC_API_KEY
    # field overrides:
    host_field: host.name
    rule_field: rule.uuid           # rule.uuid for Detection Engine alerts
    tag_field: tags
```

## Splunk

eyeexam runs Splunk searches synchronously: create job → poll until DONE
→ fetch results. Tune `poll_interval` and `max_polls` for slow searches.

```yaml
detectors:
  - name: splunk
    type: splunk
    url: https://splunk.lab:8089
    token_env: EYEEXAM_SPLUNK_TOKEN
    app: search
    default_index: main             # prepended to every SPL: `index=main ...`
    host_field: host
    poll_interval: 2s
    max_polls: 60
```

## Health checks

`eyeexam serve` and `eyeexam run` build the detector registry once. Each
detector exposes `HealthCheck`, called by future iterations of `eyeexam
inventory check` (M2 covers ssh; detector health is an M6+ enhancement).
For now the easiest probe is to run a real `eyeexam run --pack builtin`
and inspect `runs show <id>` — detector errors surface in the per-
expectation `reason` field as `detector errors: <name>: <error>`.
