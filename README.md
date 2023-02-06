# Manifest Github Action
Use this action to upload a generated SBOM to your Manifest account. Requires a Manifest API key.

## Inputs

Note that any empty value provided to the input will result in a using the default values. Also note, that for some values, if they already exists in the generated SBOM, the values from the SBOM will be used.

### `apiKey`
**REQUIRED**
`{STRING}`

Your Manifest API key. Generate this key in the Manifest Cyber app (https://app.manifestcyber.com), and then store it in your Github actions secrets.

### `bomFilePath`
**REQUIRED**
`{STRING}`

The location of a generated SBOM file. Accepts CycloneDX or SPDX SBOMs in JSON (recommended), XML, or SPDX tag:value format.

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

### `sbom-name`
**Optional**
`{STRING}`

The SBOM name. For usecases where you want to override the generated SBOM name. Default: repository name.

### `sbom-version`
**Optional**
`{STRING}`

The SBOM version. For usecases where you want to override the generated SBOM version. Default: v0.0.0-date-sha1.

### `sbom-output`
**Optional**
`{STRING}`

The SBOM output format, this is needed when passing spdx-json SBOM files.
Default: cyclonedx-json.


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
    sbom-output: spdx-json
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
    sbom-name: ${{ env.GITHUB_JOB }}-${{ env.GITHUB_REPOSITORY_OWNER }}
    sbom-version: v1.0.0-${{ steps.set-date.outputs.date }}-${{ steps.set-sha.outputs.sha }}
    sbom-output: cyclonedx-json
```


## Local Testing
An example SBOM `test-sbom-example.json` is included, as well as a `dev` script in `package.json` for local testing.
