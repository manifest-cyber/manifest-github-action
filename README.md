# Manifest Github Action
Use this action to upload a generated SBOM to your Manifest account. Requires a Manifest API key.

## Inputs

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


## Example Usage
The below example shows how you might a) generate an SBOM via CycloneDX, and b) transmit the SBOM directly to your Manifest account.

```
- name: Build SBOM
  uses: CycloneDX/gh-node-module-generatebom@master
  with:
    path: "./"
    output: "./bom.json"
- name: Transmit own SBOM
  uses: manifest-cyber/manifest-github-action@main
  id: transmit
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
    bomFilePath: "./bom.json"
    relationship: "first"
```


## Local Testing
An example SBOM `test-sbom-example.json` is included, as well as a `dev` script in `package.json` for local testing.
