# Manifest Github Action
Use this action to generator and/or upload a generated SBOM to your Manifest account. **Requires a Manifest API key.**

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

### `bomOutput`
**Optional**
`{STRING}`

The SBOM output format, this is needed when passing spdx-json SBOM files.

Default: `cyclonedx-json`.

### `bomName`
**Optional**
`{STRING}`

The SBOM name. For usecases where you want to override the generated SBOM name. 

Default: repository name.

### `bomPublish`
**Optional**
`{STRING}`

Whether to upload the SBOM to your Manifest account. 

Accepted values: `true` and `false`.  Default: `false`.

### `bomLabels`
**Optional**
`{STRING}`

Labels function as tags for your SBOMs. They are useful for organizing your SBOMs in the Manifest app.

Accepts a comma-separated list of labels. For example: `frontend,production,core,customer-facing`.

### `bomVersion`
**Optional**
`{STRING}`

The SBOM version. For usecases where you want to override the generated SBOM version. 

Defaults to environment variable tag, or commit hash.

### `relationship`
**Optional**
`{STRING}`

The relationship of the software to your organization (e.g. first- vs third-party). In most cases, this will be `first`.

Accepted values: `first`, `third`. Default: `first`.

### `source`
**Optional**
`{STRING}`

The source of the uploaded SBOM. This will be visible to you in the Manifest app and is intended for tracking/analytics purposes. We generally recommend not to change this, but you do you :)

Accepts any string. Default: `github-action`.

### `path`
**Optional**
`{STRING}`

The root path of the source code to generate the SBOM for. This is needed if you are using this action to generate an SBOM and use a non-default checkout path.

Default: `./bom.json`.

### `bomArtifact`
**Optional**
`{STRING}`

SBOMs by default are saved as artifacts within your GitHub repository action runs.

An artifact will not be created when set to anything other than `true`.

## Usage
The below example shows how you might:
a) generate an SBOM via CycloneDX, and 
b) transmit the SBOM directly to your Manifest account.

### Basic usage
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
    relationship: "first"
```

In the above example, the values of `name` and `version` will be either default values, or the SBOM values if they exists.

### Basic usage with Syft

```
- name: Build SBOM
  uses: anchore/sbom-action@v0
    with:
      path: .
      output-file: ./bom.json
      artifact-name: bom.json
      format: spdx-json
- name: Transmit own SBOM
  uses: manifest-cyber/manifest-github-action@main
  id: transmit
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
    bomFilePath: ./bom.json
    relationship: "first"
    bomOutput: spdx-json
```

Note that by using Syft, you can generate SBOMs for many ecosystems such as Golang, Node, PHP and Python. 
You can also configure it to export in different formats, make sure you are exporting to either `spdx-json` or `cyclonedx-json` and that you pass the same format to `sbom-output` in the manifestcyber action step.

See [sbom-action](https://github.com/anchore/sbom-action) repository for more information and additional configuration options.

### Using custom values for name and version
```
- name: Build SBOM
  uses: anchore/sbom-action@v0
    with:
      path: .
      output-file: ./bom.json
      artifact-name: bom.json
      format: cyclonedx-json
- name: Set version
  id: set-date
  run: echo "date=$(date '+%Y-%m-%d')" >> $GITHUB_OUTPUT
- name: Set short sha
  id: set-sha
  run: echo "sha=$(git rev-parse --short $GITHUB_SHA)" >> $GITHUB_OUTPUT
- name: Transmit own SBOM
  uses: manifest-cyber/manifest-github-action@main
  id: transmit
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
    bomFilePath: ./bom.json
    relationship: "first"
    bomName: ${{ env.GITHUB_JOB }}-${{ env.GITHUB_REPOSITORY_OWNER }}
    bomVersion: v1.0.0-${{ steps.set-date.outputs.date }}-${{ steps.set-sha.outputs.sha }}
    bomOutput: cyclonedx-json
```


## Local Testing
An example SBOM `test-sbom-example.json` is included, as well as a `dev` script in `package.json` for local testing.
