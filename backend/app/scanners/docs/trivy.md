# Trivy Adapter

**ID:** `trivy` · **Phase:** 4 · **Capability:** code · **Active:** nein

## Binary
`trivy` auf PATH (Release-Binary / WSL / Docker-Wrapper).

## Scope
`path`

## Defaults
`trivy fs --format json --exit-code 0 --quiet`
- quick: Scanner `vuln`, Severity HIGH+CRITICAL
- standard/deep: `vuln,misconfig,secret`

## Fehlendes Binary
`not installed` → Task failed ohne Fake-Findings.
