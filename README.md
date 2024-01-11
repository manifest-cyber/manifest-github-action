# Manifest Github Action

Use this action to generator and/or upload a generated SBOM to your Manifest account. **Requires a Manifest API key.**

This action will also install all required dependencies including generators, signers etc.

---

## Getting Started

### Generating an SBOM

The [examples/generate.yml](examples/generate.yml) file shows how you can use this action to generate an SBOM in your workflow.
To use this template, copy the contents of the file into your workflow directory `.github/workflows/` and then modify the template to match your needs.

By default, if the template is left unmodified, then an SBOM will be generated using [syft](https://github.com/anchore/syft) as the generator and [CycloneDX](https://github.com/CycloneDX/specification) as the format.

### Uploading an SBOM

The [examples/publish.yml](examples/publish.yml) file shows how you can use this action to transmit an SBOM to your Manifest account.
This template should only be used if some other third-party tool is generating the SBOM for you, and you want to transmit it to your Manifest account.

Note: the SBOM generation must occur prior to the SBOM upload.

### Generating and Uploading an SBOM

The [examples/generate-and-publish.yml](examples/generate-and-publish.yml) file shows how you can use this action to generate and transmit an SBOM to your Manifest account.

---

## Inputs

Note that any empty value provided to the input will result in a using the default values. Also note, that for some values, if they already exists in the generated SBOM, the values from the SBOM will be used.

### Required Inputs (Publish)

### `apiKey`

**REQUIRED FOR UPLOADING** `{STRING}`

Your Manifest API key. Generate this key in the Manifest Cyber app (https://app.manifestcyber.com), and then store it in your Github repository secrets.

### `bomFilePath`

**REQUIRED FOR UPLOADING BUT NOT GENERATING** `{STRING}`

The path of the SBOM to upload. This is useful if you are generating the SBOM in a different step (not using this action), and want to upload it (using this action) in a later step.

Accepts CycloneDX or SPDX SBOMs in JSON (recommended), XML, or SPDX tag:value format.

### `path`

**Optional**
`{STRING}`

Sets the root path of the source code to generate the SBOM for. This is needed if you are using this action to generate an SBOM and use a non-default checkout path.

### `relationship`

**Optional**
`{STRING}`

Sets the relationship of the SBOM. Must be either "first" or "third" with most cases being "first" for SBOMs generated using the GitHub action.
Default: `first`.

### `source`

**Optional**
`{STRING}`

The source of the uploaded SBOM. This will be visible to you in the Manifest app and is intended for tracking/analytics purposes. We generally recommend not to change this, but you do you :)

Accepts any string. Default: `github-action`.

### `sbomName`

**Optional**
`{STRING}`

The SBOM name, defaults to repository name.

### `sbomVersion`

**Optional**
`{STRING}`

The SBOM version, defaults to environment variable tag, or commit hash.

### `sbomOutput`

**Optional**
`{STRING}`

The SBOM output format, this is needed when passing spdx-json SBOM files.

Default: `cyclonedx-json`.

### `sbomGenerator`

**Optional**
`{STRING}`

The SBOM generator, defaults to syft. Supports: syft | trivy | cdxgen | sigstore-bom | spdx-sbom-generator | docker-sbom.
Default: `syft`.

### `sbomPublish`

**Optional**
`{STRING}`

Boolean to publish the SBOM to the Manifest Cyber platform. Expects either `true` or `false`. When unset, the action will upload if an API Key is present.

### `sbomLabels`

**Optional**
`{STRING}`

A comma separated list of labels to apply to the SBOM. Note that spaces will be replaced with a dash (-) character.

### `sbomGeneratorFlags`

**Optional**
`{STRING}`

ADVANCED USERS: Flags the Manifest CLI passes through to the generator.

---

## Usage

### Basic

```
- uses: actions/checkout@v2
- name: Generate SBOM
    uses: manifest-cyber/manifest-github-action@main
    id: generate
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
```

In this example, all depedencies would be installed by the action, generating an SBOM from source code and publishing to Manifest platform.

### Publish only

```
- name: Build SBOM
  uses: CycloneDX/gh-node-module-generatebom@master
  with:
    path: ./
    output: ./bom.json
- name: Transmit own SBOM
  uses: manifest-cyber/manifest-github-action@main
  id: transmit
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
    bomFilePath: ./bom.json
```

### Usage with arguments passthrough

```
- uses: actions/checkout@v4
- name: generate SBOM
uses: manifest-cyber/manifest-github-action@main
with:
  apiKey: ${{ secrets.MANIFEST_API_KEY }}
  sbomGenerator: syft
  sbomGeneratorFlags: --exclude=**/testdata/**
```

### Using custom values for name and version

```
- name: Set version
  id: set-date
  run: echo "date=$(date '+%Y-%m-%d')" >> $GITHUB_OUTPUT
- name: Set short sha
  id: set-sha
  run: echo "sha=$(git rev-parse --short $GITHUB_SHA)" >> $GITHUB_OUTPUT
- name: generate SBOM
  uses: manifest-cyber/manifest-github-action@main
  id: transmit
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
    sbomName: ${{ env.GITHUB_JOB }}-${{ env.GITHUB_REPOSITORY_OWNER }}
    sbomVersion: v1.0.0-${{ steps.set-date.outputs.date }}-${{ steps.set-sha.outputs.sha }}
    sbomOutput: cyclonedx-json
```

## Local Testing

An example SBOM `test-sbom-example.json` is included, as well as a `dev` script in `package.json` for local testing.
