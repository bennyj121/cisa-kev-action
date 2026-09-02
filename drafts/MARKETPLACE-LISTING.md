# Atlas HITL draft for cisa-kev-action

**Do not open the Marketplace listing editor from this draft.** Rogue does not open the listing UI. Morning Atlas acts as Benjamin.

## Repo
https://github.com/bennyj121/cisa-kev-action
New Action. No tag yet.
Cleaned main (CI smoke included): **54ff5dd2b87a00f4f743cfd965de083b75847994**
Do **not** tag from scaffold-only **4c6e3ec7** (no CI).

## Morning must (before Marketplace publish)
Cut a **new release tag v0.1.0** from cleaned main **54ff5dd2** (CI smoke included; not 4c6e3ec7). Publish Marketplace against v0.1.0. Overnight: do not create the tag, do not create a release, do not publish.

## Short description
`Fetch CISA KEV catalog JSON, optional since-date change detect.`

## About
Free composite GitHub Action that fetches the public CISA Known Exploited Vulnerabilities catalog JSON (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, no API key). Optional since-date change-detect on dateAdded. Live results are capped (default 2000, max 5000). Writes a step summary (count, newest CVE, optional change-count). Fail-soft on upstream blips.

Positioning: free utilities / Continuous integration. No paid SKU, no Ko-fi, no $40, no hospital MRF-change extract.

Built by Rogue, an AI agent, not a human. Not a CISA or DHS product. CISA and DHS do not endorse this Action.

## Steps (UI) — Atlas only, morning HITL
1. Confirm main is still 54ff5dd2 (or a later commit that keeps the CI smoke and the $40 CTA strip). Do **not** tag 4c6e3ec7.
2. Create **new** GitHub release tag **v0.1.0** pointing at **54ff5dd2**. There is no prior tag to retag.
3. Then use Draft a release / Publish this Action to the GitHub Marketplace from **v0.1.0**.
4. Primary category: Continuous integration (or Monitoring if offered).
5. Paste the short description above (free utilities; do not lead with a paid signal).
6. Confirm branding from action.yml (shield / red).

## Out
- Rogue opening the listing editor
- Overnight tag/release/publish
- Live-card UI edits
- Cold email / Reddit / HN / any post
- No package registries
- Paid CTAs / Ko-fi / paid extract / hospital MRF-change SKU
- Implying CISA or DHS endorsement
- Tagging scaffold-only 4c6e3ec7
