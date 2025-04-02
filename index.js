const fs = require("fs");
const path = require("path");
const core = require("@actions/core");
const { DefaultArtifactClient } = require("@actions/artifact");
const artifactClient = new DefaultArtifactClient();
const { exec } = require("child_process");
const util = require("util");
const semver = require("semver");

const execPromise = util.promisify(exec);

const manifestBinary = "manifest-cli";

// Use the official install script from GitHub.
const remoteInstallScriptURL =
  "https://raw.githubusercontent.com/manifest-cyber/cli/main/install.sh";

// Helper to get the current date formatted as YYYYMMDDHHMMSS.
function getCurrentDateFormatted() {
  const now = new Date();
  const pad = (n) => n.toString().padStart(2, "0");
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(
    now.getDate()
  )}${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

async function execWrapper(cmd) {
  try {
    const { stdout, stderr } = await execPromise(cmd);
    if (stdout) {
      console.log(`stdout: ${stdout}`);
    }
    if (stderr) {
      console.log(`stderr: ${stderr}`);
    }
  } catch (error) {
    core.setFailed(`Error executing command: ${cmd}\n${error}`);
    throw error;
  }
}

function fileExists(filePath) {
  return fs.existsSync(filePath);
}

function validateInput(output, generator) {
  const validOutput = ["spdx-json", "cyclonedx-json"];
  const validGenerator = [
    "syft",
    "trivy",
    "cdxgen",
    "sigstore-bom",
    "spdx-sbom-generator",
    "docker-sbom",
  ];
  if (output && !validOutput.includes(output)) {
    throw new Error(
      `Invalid output format: ${output}, expected one of ${validOutput}`
    );
  }
  if (generator && !validGenerator.includes(generator)) {
    throw new Error(
      `Invalid generator: ${generator}, expected one of ${validGenerator}`
    );
  }
}

function shouldPublish(apiKey, publish) {
  return apiKey && publish !== "false";
}

// Generate the SBOM by invoking manifest-cli.
async function generateSBOM(
  targetPath,
  outputPath,
  outputFormat,
  sbomName,
  sbomVersion,
  generator,
  generatorVersion,
  generatorPreset,
  generatorConfig,
  generatorFlags
) {
  if (fileExists(outputPath)) {
    return outputPath;
  }
  validateInput(outputFormat, generator);
  let sbomFlags = `--file=${outputPath} --output="${outputFormat}" --name="${sbomName}" --version="${sbomVersion}" --generator="${generator}" --publish=false ${targetPath}`;
  if (generatorFlags) {
    sbomFlags = `${sbomFlags} -- ${generatorFlags}`;
  }

  // Set default generator versions if not provided.
  if (generator === "syft" && generatorVersion === "") {
    generatorVersion = "v1.19.0";
  }
  if (generator === "trivy" && generatorVersion === "") {
    generatorVersion = "v0.59.1";
  }
  if (generator === "cdxgen" && generatorVersion === "") {
    generatorVersion = "v11.1.8";
  }

  const installCommand = `${manifestBinary} install --generator="${generator}" --version="${generatorVersion}"`;
  const generateCommand = `${manifestBinary} sbom --generator-preset="${generatorPreset}" --generator-config="${generatorConfig}" ${sbomFlags}`;

  core.info(`Installing generator using command: ${installCommand}`);
  await execWrapper(installCommand);
  core.info(`Installed ${generator}`);

  core.info(`Generating SBOM using command: ${generateCommand}`);
  await execWrapper(generateCommand);

  if (fileExists(outputPath)) {
    core.info(`SBOM Generated: ${outputPath}`);
    return outputPath;
  } else {
    throw new Error(`Error generating SBOM: ${outputPath} does not exist.`);
  }
}

(async () => {
  try {
    const apiKey = core.getInput("apiKey") || core.getInput("apikey");
    core.setSecret(apiKey);

    const targetPath = core.getInput("path") || process.cwd();

    // Compute the default name.
    let name =
      core.getInput("sbomName") ||
      core.getInput("bomName") ||
      core.getInput("name");
    if (!name) {
      if (process.env.GITHUB_REPOSITORY) {
        // Default to the repository name (after the slash).
        name = process.env.GITHUB_REPOSITORY.split("/")[1];
      } else {
        name = "default-name";
      }
    }

    const bomFilePath =
      core.getInput("sbomFilePath") ||
      core.getInput("bomFilePath") ||
      `${name}.json`;

    // Compute the default version.
    let version =
      core.getInput("sbomVersion") ||
      core.getInput("bomVersion") ||
      core.getInput("version") ||
      "";
    if (!version) {
      let gittag = "";
      if (process.env.GITHUB_REF_TYPE === "tag") {
        gittag = process.env.GITHUB_REF_NAME;
      }
      if (gittag) {
        version = gittag;
      } else {
        const currentdate = getCurrentDateFormatted();
        const shortsha = process.env.GITHUB_SHA
          ? process.env.GITHUB_SHA.substring(0, 7)
          : "unknown";
        version = `v0.0.0-${currentdate}-${shortsha}`;
      }
    }

    const output =
      core.getInput("sbomOutput") ||
      core.getInput("sbom-output") ||
      core.getInput("bomOutput");
    const generator =
      core.getInput("sbomGenerator") ||
      core.getInput("bomGenerator") ||
      core.getInput("generator") ||
      "syft";
    const generatorVersion = core.getInput("generator-version") || "";
    const generatorConfig = core.getInput("generator-config") || "";
    const generatorPreset = core.getInput("generator-preset") || "";
    const artifact =
      core.getInput("sbomArtifact") || core.getInput("bomArtifact");
    const publish =
      core.getInput("sbomPublish") ||
      core.getInput("bomPublish") ||
      core.getInput("publish");
    const generatorFlags =
      core.getInput("sbomGeneratorFlags") ||
      core.getInput("bomGeneratorFlags") ||
      core.getInput("generator-flags");
    const source = core.getInput("source");
    const relationship = core.getInput("relationship");
    const active = core.getInput("active");
    const enrich = core.getInput("enrich");
    const assetLabels =
      core.getInput("sbomLabels") ||
      core.getInput("bomLabels") ||
      core.getInput("asset-labels") ||
      "";
    const apiURI = core.getInput("apiURI");
    const productLabels = core.getInput("product-labels") || "";
    const productId = core.getInput("product-id") || "";

    // Install the Manifest CLI using the remote install.sh script.
    const installDir = path.join(process.cwd(), ".manifest");
    const installCommand = `curl -sSfL ${remoteInstallScriptURL} | sh -s -- -b ${installDir}`;
    core.info(`Installing Manifest CLI using command: ${installCommand}`);
    await execWrapper(installCommand);
    core.info("Manifest CLI installed.");
    process.env.PATH = `${installDir}:${process.env.PATH}`;

    const outputPath = await generateSBOM(
      targetPath,
      bomFilePath,
      output,
      name,
      version,
      generator,
      generatorVersion,
      generatorPreset,
      generatorConfig,
      generatorFlags
    );

    // Optionally upload the SBOM as an artifact.
    if (outputPath && artifact === "true") {
      const upload = await artifactClient.uploadArtifact(
        "sbom",
        [outputPath],
        path.dirname(outputPath)
      );
      core.info(`SBOM uploaded to GitHub as an artifact: ${upload}`);
    }

    // Optionally publish the SBOM if an API key is provided.
    if (shouldPublish(apiKey, publish)) {
      let publishCommandParts = [
        `MANIFEST_API_KEY=${apiKey}`,
        `${manifestBinary}`,
        `publish`,
        `--ignore-validation="true"`,
      ];
      if (apiURI) {
        publishCommandParts.push(`--api-uri="${apiURI}"`);
      }
      if (source) {
        publishCommandParts.push(`--source="${source}"`);
      }
      if (relationship) {
        publishCommandParts.push(`--relationship="${relationship}"`);
      }
      if (active) {
        publishCommandParts.push(`--active="${active}"`);
      }
      if (enrich) {
        publishCommandParts.push(`--enrich="${enrich.toUpperCase()}"`);
      }
      publishCommandParts.push(bomFilePath);
      let publishCommand = publishCommandParts.join(" ");
      publishCommand = `${publishCommand} --source="github-action"`;
      publishCommand = `${publishCommand} --asset-label="${assetLabels
        .split(",")
        .map((label) => label.trim())
        .filter((label) => label !== "")
        .join(",")}"`;
      publishCommand = `${publishCommand} --product-label="${productLabels
        .split(",")
        .map((label) => label.trim())
        .filter((label) => label !== "")
        .join(",")}"`;
      publishCommand = `${publishCommand} --product-id="${productId}"`;
      core.info("Sending request to Manifest Server");
      await execWrapper(publishCommand);
    } else {
      core.info("No API Key provided, skipping publish");
    }
  } catch (error) {
    core.setFailed(error.message);
  }
})();
