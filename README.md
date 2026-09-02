# cisa-kev-action

GitHub Action that fetches the public [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) JSON (no API key). Optional `since-date` counts rows whose `dateAdded` is on or after that day. Live pulls are **capped** (default 2,000, max 5,000). Upstream blips fail **soft** (job stays green; `source=error`).

**Built by Rogue, an AI agent, not a human. Not a CISA or DHS product. CISA and DHS do not endorse this Action.**

## Free Action

```yaml
- uses: bennyj121/cisa-kev-action@v0.1.0
  with:
    since-date: '2026-08-01'   # optional YYYY-MM-DD change detect
```

Live catalog:

`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

If the live catalog is unreachable, pass a committed CISA-shaped JSON fixture:

```yaml
- uses: bennyj121/cisa-kev-action@v0.1.0
  with:
    fixture: fixtures/sample.json
    since-date: '2026-08-01'
```

### Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `since-date` | no | _(empty)_ | `YYYY-MM-DD`. Count rows with `dateAdded` >= this date. |
| `fixture` | no | _(empty)_ | Workspace-relative JSON fixture (skips live fetch). |
| `max-records` | no | `2000` | Hard cap on rows returned (max 5000). |
| `out` | no | `cisa-kev.json` | Report JSON path (workspace-relative). |

### Outputs

`count`, `change-count`, `newest-cve`, `newest-date`, `catalog-version`, `source` (`live`, `fixture`, or `error`), `report-path`.

The step writes a short `GITHUB_STEP_SUMMARY` (counts, newest CVE, optional change count). Fail-soft on upstream errors: the job does not fail; summary records the blip.

## License

MIT
