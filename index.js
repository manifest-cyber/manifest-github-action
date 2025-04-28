const fs = require("fs");
const path = require("path");
const os = require("os");
const core = require("@actions/core");
const { DefaultArtifactClient } = require("@actions/artifact");
const artifactClient = new DefaultArtifactClient();
const { exec } = require("child_process");
const util = require("util");
const cliVersionInput = core.getInput("manifest-cli-version");
const cliVersionToInstall = cliVersionInput || "latest";
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
    // Print whatever the child process emitted before it failed:
    if (error.stdout) {
      console.log(`stdout: ${error.stdout}`);
    }
    if (error.stderr) {
      console.log(`stderr: ${error.stderr}`);
    }
    // Now fail the Action with the full error
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
  generatorFlags,
  verbose,
  installDir
) {
  if (fileExists(outputPath)) {
    return outputPath;
  }
  validateInput(outputFormat, generator);

  // Build SBOM flags
  let sbomFlags = `--file=${outputPath} --output="${outputFormat}" --name="${sbomName}" --version="${sbomVersion}" --generator="${generator}" --publish=false ${targetPath}`;
  if (verbose === "true") sbomFlags += " -vvv";
  if (generatorFlags) sbomFlags += ` -- ${generatorFlags}`;

  // Default versions
  if (!generatorVersion) {
    if (generator === "syft") generatorVersion = "v1.19.0";
    if (generator === "trivy") generatorVersion = "v0.59.1";
    if (generator === "cdxgen") generatorVersion = "v11.1.8";
  }

  const installCommand = `${manifestBinary} install --generator="${generator}" --version="${generatorVersion}" --destination="${installDir}"`;
  core.info(`Installing generator using command: ${installCommand}`);

  if (generator === "cdxgen" && process.platform !== "win32") {
    // On *nix, ensure cdxgen ends up on PATH
    const npmVer = generatorVersion.replace(/^v/, "");
    const npmCmd = `npm install -g @cyclonedx/cdxgen@${npmVer}`;
    core.info(`Fallback npm install for cdxgen: ${npmCmd}`);
    await execWrapper(npmCmd);
  } else {
    await execWrapper(installCommand);
  }
  core.info(`Installed ${generator}`);

  // Verify generator is available
  const genBinary =
    process.platform === "win32" ? `${generator}.exe` : generator;
  core.info(`Checking availability of generator executable: ${genBinary}`);
  try {
    await execWrapper(`${genBinary} --version`);
    core.info(`${genBinary} is available`);
  } catch (err) {
    core.setFailed(`Generator ${genBinary} is not on PATH`);
    throw err;
  }

  // Now generate
  const generateCommand = `${manifestBinary} sbom --generator-preset="${generatorPreset}" --generator-config="${generatorConfig}" ${sbomFlags}`;
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
    if (apiKey) process.env.MANIFEST_API_KEY = apiKey;

    const targetPath = core.getInput("path") || process.cwd();

    // Default name
    let name =
      core.getInput("sbomName") ||
      core.getInput("bomName") ||
      core.getInput("name") ||
      (process.env.GITHUB_REPOSITORY || "").split("/")[1] ||
      "default-name";

    const bomFilePath =
      core.getInput("sbomFilePath") ||
      core.getInput("bomFilePath") ||
      `${name}.json`;

    // Default version
    let version =
      core.getInput("sbomVersion") ||
      core.getInput("bomVersion") ||
      core.getInput("version") ||
      "";
    if (!version) {
      const tagName =
        process.env.GITHUB_REF_TYPE === "tag"
          ? process.env.GITHUB_REF_NAME
          : "";
      version =
        tagName ||
        `v0.0.0-${getCurrentDateFormatted()}-${(
          process.env.GITHUB_SHA || "unknown"
        ).substring(0, 7)}`;
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
    const verbose = core.getInput("verbose");

    if (verbose === "true") core.info("Verbose mode enabled");

    // Install manifest-cli
    const installDir = fs.mkdtempSync(path.join(os.tmpdir(), "manifest-cli-"));
    const manifestInstallCmd = `curl -sSfL ${remoteInstallScriptURL} | sh -s -- -b ${installDir} ${cliVersionToInstall}`;
    core.info(`Installing Manifest CLI: ${manifestInstallCmd}`);
    await execWrapper(manifestInstallCmd);
    core.info("Manifest CLI installed.");

    // Prepend to PATH
    process.env.PATH = `${installDir}${path.delimiter}${process.env.PATH}`;

    // Generate SBOM
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
      installDir
    );

    // Upload as artifact
    if (outputPath && artifact === "true") {
      const upload = await artifactClient.uploadArtifact(
        `sbom-${name}-${version}`,
        [outputPath],
        path.dirname(outputPath)
      );
      core.info(`SBOM uploaded as artifact: ${upload}`);
    }

    // Publish if requested
    if (shouldPublish(apiKey, publish)) {
      let parts = [manifestBinary, "publish", `--ignore-validation="true"`];
      if (apiURI) parts.push(`--api-uri="${apiURI}"`);
      if (source) parts.push(`--source="${source}"`);
      if (relationship) parts.push(`--relationship="${relationship}"`);
      if (active) parts.push(`--active="${active}"`);
      if (enrich) parts.push(`--enrich="${enrich.toUpperCase()}"`);
      if (verbose === "true") parts.push("-vvv");
      parts.push(bomFilePath);

      let cmd = parts.join(" ");
      cmd = `${cmd} --source="github-action"`;
      cmd = `${cmd} --asset-label="${assetLabels
        .split(",")
        .map((l) => l.trim())
        .filter(Boolean)
        .join(",")}"`;
      cmd = `${cmd} --product-label="${productLabels
        .split(",")
        .map((l) => l.trim())
        .filter(Boolean)
        .join(",")}"`;
      cmd = `${cmd} --product-id="${productId}"`;

      core.info("Publishing SBOM to Manifest Server");
      await execWrapper(cmd);
    } else {
      core.info("No API Key, skipping publish");
    }
  } catch (error) {
    core.setFailed(error.message);
  }
})();
