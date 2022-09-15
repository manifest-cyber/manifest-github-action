# Manifest Github Action

This action sends a generated SBOM to a Manifest Cyber account

## Inputs

### `apiKey`

**Required** An API key. Generate this key in the Manifest Cyber app, and then store it in your Github actions secrets.

### `bomFilePath`

**Required** The location of a BOM file. Accepts CycloneDX or SPDX SBOMs in JSON, XML, or SPDX tag:value format.


## Example usage

```
- name: Build SBOM
  uses: CycloneDX/gh-node-module-generatebom@master
  with:
    path: "./"
    output: "./bom.json"
- name: Transmit own SBOM
  uses: @manifest/manifest-github-action@main
  id: transmit
  with:
    apiKey: ${{ secrets.MANIFEST_API_KEY }}
    bomFilePath: "./bom.json"
```