# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A GitHub Action that generates and uploads Software Bill of Materials (SBOMs) to the Manifest Cyber platform. It orchestrates the external `manifest-cli` binary to install SBOM generators, generate SBOMs, upload them as GitHub artifacts, and publish them to Manifest's API.

## Development Commands

```bash
# Test locally with a pre-existing SBOM file (no generation)
npm run dev

# Test SBOM generation with specific generator/format combos
npm run dev:syft-spdx
npm run dev:syft-cdx
npm run dev:trivy-spdx
npm run dev:trivy-cdx
```

All dev scripts set `TEST_LOCALLY=enabled` and simulate GitHub Actions environment variables. Replace `<MANIFEST_API_KEY>` in package.json scripts with a real key to test publishing.

There is no test suite, linter, or type checker configured.

## Architecture

**Single-file action** -- all logic lives in [index.js](index.js) (~318 lines). The action is defined in [action.yml](action.yml) and runs on Node.js 20.

### Execution flow

1. **Parse inputs** -- reads GitHub Actions inputs via `core.getInput()` with multiple alias names per parameter (e.g., `sbomName` / `bomName` / `name`). Defaults SBOM name to repo name and version to git tag or `v0.0.0-{timestamp}-{shortsha}`.
2. **Install manifest-cli** -- downloads install script from GitHub, installs binary to a temp directory, adds to PATH. Supports pinning a specific CLI version.
3. **Generate SBOM** -- `generateSBOM()` installs the chosen generator (`manifest-cli install`) then runs `manifest-cli sbom`. Supported generators: syft, trivy, cdxgen, sigstore-bom, spdx-sbom-generator, docker-sbom, csbom. Output formats: cyclonedx-json, spdx-json.
4. **Upload artifact** -- optionally uploads SBOM as a GitHub artifact via `@actions/artifact`.
5. **Publish** -- if API key is present and publish is not `false`, runs `manifest-cli publish` with labels, product ID, relationship, enrichment options, etc.

### Key patterns

- **Input aliasing**: Many inputs have legacy and current names joined with `||` chains. When adding a new alias, follow the existing pattern and update [action.yml](action.yml).
- **Command construction**: Commands are built as arrays of string parts (`publishCommandParts`), then joined with spaces. Labels are cleaned via split/trim/filter/join.
- **Platform handling**: Binary name is `manifest-cli.exe` on Windows, `manifest-cli` elsewhere.
- **Error handling**: `execWrapper()` logs stdout/stderr from failed child processes before calling `core.setFailed()`.

## CI

[.github/workflows/main.yml](.github/workflows/main.yml) runs on push to `main` and version tags (`v*`). It checks out the repo and runs the action itself using `manifest-cyber/manifest-github-action@main` with the syft generator.

## Adding a New Input Parameter

1. Add the input definition in [action.yml](action.yml)
2. Read it in [index.js](index.js) with `core.getInput()`, supporting any legacy aliases with `||`
3. Wire it into the relevant command construction (generate or publish)

## Adding a New Generator

1. Add the generator name to the `validGenerator` array in `validateInput()` ([index.js:55](index.js#L55))
2. The generator must be supported by manifest-cli's `install` and `sbom` commands
3. Optionally add a dev script in [package.json](package.json)
