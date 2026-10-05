const fs = require("fs");
const path = require("path");
const os = require("os");
const core = require("@actions/core");
const { DefaultArtifactClient } = require("@actions/artifact");
const artifactClient = new DefaultArtifactClient();
const { exec } = require("child_process");
const util = require("util");
const execPromise = util.promisify(exec);

const manifestBinary =
  process.platform === "win32" ? "manifest-cli.exe" : "manifest-cli";
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

async function execWrapper(cmd, { failAction = true } = {}) {
  try {
    const { stdout, stderr } = await execPromise(cmd);
    if (stdout) {
      console.log(`stdout: ${stdout}`);
    }
    if (stderr) {
      console.log(`stderr: ${stderr}`);
    }
  } catch (error) {
    // Print whatever the child process emitted before it failed:
    if (error.stdout) {
      console.log(`stdout: ${error.stdout}`);
    }
    if (error.stderr) {
      console.log(`stderr: ${error.stderr}`);
    }
    // Now fail the Action with the full error
    if (failAction) {
      core.setFailed(`Error executing command: ${cmd}\n${error}`);
    }
    throw error;
  }
}

function fileExists(filePath) {
  return fs.existsSync(filePath);
}

// Generators that `manifest-cli install` places in --destination under their own name.
const destinationGenerators = ["syft", "trivy", "spdx-sbom-generator"];
const generatorInstallAttempts = 3;
const generatorInstallRetryDelayMs = 5000;

function binaryName(name) {
  return process.platform === "win32" ? `${name}.exe` : name;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Retry until the binary exists, because the install command can exit zero
// without having installed anything.
async function installGeneratorWithRetry(
  installCommand,
  generator,
  binaryPath,
  installDir
) {
  for (let attempt = 1; attempt <= generatorInstallAttempts; attempt++) {
    let installed = false;
    try {
      await execWrapper(installCommand, { failAction: false });
      installed = true;
    } catch (error) {
      core.info(`Install attempt ${attempt} failed: ${error.message}`);
      // A failed attempt can leave a partial binary that would pass the existence check.
      fs.rmSync(binaryPath, { force: true });
    }
    if (installed && fileExists(binaryPath)) {
      return;
    }
    if (attempt < generatorInstallAttempts) {
      core.info(
        `${generator} not found at ${binaryPath} after install attempt ${attempt}, retrying in ${
          generatorInstallRetryDelayMs / 1000
        }s`
      );
      await sleep(generatorInstallRetryDelayMs);
    }
  }
  throw new Error(
    `Failed to install ${generator}: ${binaryName(
      generator
    )} not found in ${installDir} after ${generatorInstallAttempts} attempts.`
  );
}

function validateInput(output, generator, detectAI) {
  const validOutput = ["spdx-json", "cyclonedx-json"];
  const validGenerator = [
    "syft",
    "trivy",
    "cdxgen",
    "sigstore-bom",
    "spdx-sbom-generator",
    "docker-sbom",
    "csbom",
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
  if (detectAI === "true" && output && output !== "cyclonedx-json") {
    throw new Error("`detect-ai` requires `cyclonedx-json` output format.");
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
  generatorFlags,
  verbose,
  installDir,
  detectAI,
  installDependencies
) {
  if (fileExists(outputPath)) {
    return outputPath;
  }
  validateInput(outputFormat, generator, detectAI);
  let sbomFlags = `--file=${outputPath} --output="${outputFormat}" --name="${sbomName}" --version="${sbomVersion}" --generator="${generator}" --publish=false`;
  if (detectAI === "true") {
    sbomFlags = `${sbomFlags} --detect-ai`;
  }
  if (installDependencies === "true") {
    sbomFlags = `${sbomFlags} --install-dependencies`;
  }
  if (verbose === "true") {
    sbomFlags = `${sbomFlags} -vvv`;
  }
  sbomFlags = `${sbomFlags} ${targetPath}`;
  if (generatorFlags) {
    sbomFlags = `${sbomFlags} -- ${generatorFlags}`;
  }

  // If no generator version provided, use default version from manifest-cli (MaxSupportedVersion), no --version flag needed.
  let installCommand = `${manifestBinary} install --generator="${generator}" --destination="${installDir}"`;

  // If a generator version is provided, add the --version flag to the install command.
  if (generatorVersion) {
    installCommand = `${installCommand} --version="${generatorVersion}"`;
  }

  const generateCommand = `${manifestBinary} sbom --generator-preset="${generatorPreset}" --generator-config="${generatorConfig}" ${sbomFlags}`;

  if (destinationGenerators.includes(generator)) {
    const generatorBinaryPath = path.join(installDir, binaryName(generator));
    if (!generatorVersion && fileExists(generatorBinaryPath)) {
      core.info(
        `Reusing ${generator} already installed at ${generatorBinaryPath}`
      );
    } else {
      // A pinned install must not pass the existence check on a leftover binary.
      fs.rmSync(generatorBinaryPath, { force: true });
      core.info(`Installing generator using command: ${installCommand}`);
      await installGeneratorWithRetry(
        installCommand,
        generator,
        generatorBinaryPath,
        installDir
      );
      core.info(`Installed ${generator}`);
    }
  } else {
    core.info(`Installing generator using command: ${installCommand}`);
    await execWrapper(installCommand);
    core.info(`Installed ${generator}`);
  }

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
    if (apiKey) {
      process.env.MANIFEST_API_KEY = apiKey;
    }

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
    const uploadArtifactToGithub =
      core.getInput("sbomArtifact") || core.getInput("bomArtifact") || "true";
    const githubArtifactName =
      core.getInput("sbomArtifactName") ||
      core.getInput("bomArtifactName") ||
      "sbom";
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
    const deactivateOlder = core.getInput("deactivate-older");
    const deactivateLabels = core.getInput("deactivate-label");
    const replaceInProduct = core.getInput("replace-in-product");
    const enrich = core.getInput("enrich");
    const assetLabels =
      core.getInput("sbomLabels") ||
      core.getInput("bomLabels") ||
      core.getInput("asset-labels") ||
      "";
    const apiURI = core.getInput("apiURI");
    const productLabels = core.getInput("product-labels") || "";
    const productId = core.getInput("product-id") || "";

    const verbose = core.getInput("verbose");
    if (verbose === "true") {
      core.info("Verbose mode enabled");
    }

    const detectAI =
      core.getInput("detect-ai").toLowerCase() ||
      core.getInput("detectAI").toLowerCase();
    const installDependencies =
      core.getInput("install-dependencies").toLowerCase() ||
      core.getInput("installDependencies").toLowerCase();

    const cliVersionInput =
      core.getInput("manifest-cli-version") ||
      core.getInput("manifestCLIVersion");
    const cliVersionToInstall = cliVersionInput || "latest";

    console.log(`Manifest CLI version to install: ${cliVersionToInstall}`);

    // Shared by every step in the job; keyed by CLI version so a pinned step
    // does not run another step's binary.
    const installDir = path.join(
      process.env.RUNNER_TEMP || os.tmpdir(),
      "manifest-github-action",
      `manifest-cli-${cliVersionToInstall}`
    );
    fs.mkdirSync(installDir, { recursive: true });
    const cliBinaryPath = path.join(installDir, manifestBinary);
    if (fileExists(cliBinaryPath)) {
      core.info(`Reusing Manifest CLI already installed at ${cliBinaryPath}`);
    } else {
      const installCommand = `curl -sSfL ${remoteInstallScriptURL} | sh -s -- -b "${installDir}" ${cliVersionToInstall}`;
      core.info(`Installing Manifest CLI using command: ${installCommand}`);
      await execWrapper(installCommand);
      core.info("Manifest CLI installed.");
    }

    // Add the install directory to the PATH.
    process.env.PATH = `${installDir}${path.delimiter}${process.env.PATH}`;

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
      generatorFlags,
      verbose,
      installDir,
      detectAI,
      installDependencies
    );

    // Optionally upload the SBOM as an artifact.
    if (outputPath && uploadArtifactToGithub === "true") {
      const upload = await artifactClient.uploadArtifact(
        githubArtifactName,
        [outputPath],
        path.dirname(outputPath)
      );
      core.info(`SBOM uploaded to GitHub as an artifact: ${upload}`);
    }

    // Optionally publish the SBOM if an API key is provided.
    if (shouldPublish(apiKey, publish)) {
      let publishCommandParts = [
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
      if (deactivateOlder === "true") {
        publishCommandParts.push(`--deactivate-older`);
      }
      if (replaceInProduct === "true") {
        publishCommandParts.push(`--replace-in-product`);
      }
      if (enrich) {
        publishCommandParts.push(`--enrich="${enrich.toUpperCase()}"`);
      }
      if (verbose === "true") {
        publishCommandParts.push(`-vvv`);
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
      const cleanedDeactivateLabels = deactivateLabels
        .split(",")
        .map((label) => label.trim())
        .filter((label) => label !== "")
        .join(",");
      if (cleanedDeactivateLabels) {
        publishCommand = `${publishCommand} --deactivate-label="${cleanedDeactivateLabels}"`;
      }
      core.info("Sending request to Manifest Server");
      await execWrapper(publishCommand);
    } else {
      core.info("No API Key provided, skipping publish");
    }
  } catch (error) {
    core.setFailed(error.message);
  }
})();
