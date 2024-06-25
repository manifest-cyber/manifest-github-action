const fs = require("fs");
const core = require("@actions/core");
const cache = require("@actions/tool-cache");
const { DefaultArtifactClient } = require("@actions/artifact");
const artifactClient = new DefaultArtifactClient();
const { exec } = require("child_process");
const util = require("node:util");
const semver = require("semver");

const { Octokit } = require("@octokit/rest");
const octokit = new Octokit();
const manifestOwner = "manifest-cyber";
const manifestRepo = "cli";
const manifestBinary = "manifest-cli";
const jqOwner = "jqlang";
const jqRepo = "jq";
const jqBinary = "jq";
const tmpPath = "/tmp";

const execPromise = util.promisify(exec);

const validOutput = ["spdx-json", "cyclonedx-json"];
const validGenerator = [
  "syft",
  "trivy",
  "cdxgen",
  "sigstore-bom",
  "spdx-sbom-generator",
  "docker-sbom",
];
const localTest = process.env.TEST_LOCALLY;

async function execWrapper(cmd) {
  const { stdout, stderr, error } = await execPromise(cmd);
  if (stdout) {
    console.log(`stdout: ${stdout}`);
  }

  if (stderr) {
    console.log(`stderr: ${stderr}`);
    return;
  }

  if (error) {
    core.setFailed(`error: ${error}`);
    return;
  }
}

// TODO: Add better support for different platforms
async function getReleaseVersion(owner, repo, targetAsset) {
  // Pull the latest version of the CLI
  let release = await octokit.repos.getLatestRelease({ owner, repo });

  let manifestVersion = release.data?.tag_name;
  let binaryUrl = undefined;

  for (let i = 0; i < release.data?.assets?.length || 0; i++) {
    if (release.data.assets[i].name === targetAsset) {
      binaryUrl = release.data.assets[i].browser_download_url;
      break;
    }
  }

  if (!binaryUrl) {
    throw new Error("Could not find the latest release of the CLI");
  }

  return { manifestVersion, binaryUrl };
}

// TODO: Add support for caching the CLI
async function getCLI(version, url, binary) {
  const dest = `${tmpPath}${url.substring(url.lastIndexOf("/"))}`;
  const binaryPath = `${tmpPath}/${binary}`;
  if (fileExists(`${binaryPath}/${binary}`)) {
    core.info("Manifest CLI already exists, skipping download");
    core.addPath(binaryPath);
    return;
  }

  if (!fileExists(dest)) {
    core.info(`Downloading the latest version of the CLI from ${url}`);
    await cache.downloadTool(url, dest);
  } else {
    core.info("CLI tarball already exists, skipping download");
  }

  core.addPath(binaryPath);

  let binaryExtractedPath;
  if (url.endsWith(".tar.gz")) {
    binaryExtractedPath = await cache.extractTar(dest, binaryPath, "xz");
  } else {
    binaryExtractedPath = dest;
  }
  core.addPath(binaryExtractedPath);
}

function shouldPublish(apiKey, publish) {
  if (!apiKey) {
    return false;
  }

  return publish !== "false";
}

function fileExists(filePath) {
  return fs.existsSync(filePath);
}

function validateInput(output, generator) {
  if (output && !validOutput.includes(output)) {
    throw new Error(
      `Invalid output format: ${output}, expected to be one of ${validOutput}`
    );
  }
  if (generator && !validGenerator.includes(generator)) {
    throw new Error(
      `Invalid generator: ${generator}, expected to be one of ${validGenerator}`
    );
  }
}

// TODO: Add support for caching the generators that the CLI uses
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
    return;
  }
  validateInput(outputFormat, generator);
  let sbomFlags = `--file=${outputPath.replace(
    /\.json$/,
    ""
  )} --output="${outputFormat}" --name="${sbomName}" --generator="${generator}" --publish=false ${targetPath}`;
  if (sbomVersion?.length > 0) {
    sbomFlags = `${sbomFlags} --version="${sbomVersion}"`;
  }
  if (generatorFlags) {
    sbomFlags = `${sbomFlags} -- ${generatorFlags}`;
  }

  if (generator === "syft" && generatorVersion === "") {
    generatorVersion = "v1.6.0";
  }

  const installCommand =
    `${manifestBinary} install --generator="${generator}" --version="${generatorVersion}"`.replace(
      "\n",
      ""
    );
  const generateCommand =
    `${manifestBinary} sbom --generator-preset="${generatorPreset}" --generator-config="${generatorConfig}" ${sbomFlags}`.replace(
      "\n",
      ""
    );

  core.info(`Installing generator using flags: ${sbomFlags}`);
  await execWrapper(installCommand).then(async () => {
    core.info(`Installed ${generator}`);
    core.info(`Generating SBOM using: ${generateCommand}`);
    await execWrapper(generateCommand).then(() => {
      core.info(`SBOM Generated: ${outputPath}`);
    });
  });
  return outputPath;
}

try {
  const apiKey = core.getInput("apiKey") || core.getInput("apikey");
  core.setSecret(apiKey);
  const targetPath = core.getInput("path") || `${process.cwd()}`;
  const name =
    core.getInput("sbomName") ||
    core.getInput("bomName") ||
    core.getInput("name") ||
    `${process.env.GITHUB_REPOSITORY?.replace(
      `${process.env.GITHUB_REPOSITORY_OWNER}/`,
      ""
    )}`;

  const bomFilePath =
    core.getInput("sbomFilePath") ||
    core.getInput("bomFilePath") ||
    `${name}.json`;
  let version =
    core.getInput("sbomVersion") ||
    core.getInput("bomVersion") ||
    core.getInput("version");
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
  const active = core.getInput("active") || "true";
  const assetLabels =
    core.getInput("sbomLabels") ||
    core.getInput("bomLabels") ||
    core.getInput("asset-labels") ||
    "";
  const productLabels = core.getInput("product-labels") || "";
  const productId = core.getInput("product-id") || "";

  const targetManifestAsset =
    localTest && localTest === "enabled"
      ? "manifest-cli_darwin_x86_64.tar.gz"
      : "manifest-cli_linux_x86_64.tar.gz";
  const jqVersion = "1.7.1";
  const targetJqAsset =
    localTest && localTest === "enabled"
      ? `https://github.com/jqlang/jq/releases/download/jq-${jqVersion}/jq-osx-amd64`
      : `https://github.com/jqlang/jq/releases/download/jq-${jqVersion}/jq-linux64`;

  /**
   * At Manifest, we like to eat our own dogfood - you'll see some development code we use when testing our API and this action locally. We include our development code for both transparency to you and our own convenience.
   * If you have a better idea or suggested improvements, fork/PR or ping us at engineering@manifestcyber.com and we'd love to chat over a virtual cup of coffee :)
   */
  // TODO: Remove once syft support SBOM versions correctly
  if (version?.length < 1) {
    // getReleaseVersion(jqOwner, jqRepo, targetJqAsset).then(async({ jqVersion, binaryUrl }) => {
    // core.info(`found jq version ${jqVersion} at ${binaryUrl}`);
    getCLI(jqVersion, targetJqAsset, jqBinary).then(async () => {
      core.info(`jq version ${jqVersion} installed`);
      const jqVersionCommand = `cat ${targetPath}/package.json | jq '.version'`;
      const { stdout } = await execPromise(jqVersionCommand);
      if (stdout && stdout.length > 0 && stdout !== "null") {
        version = stdout;
        console.log(`extracted version ${version} from temp sbom`);
      }
    });
  }
  getReleaseVersion(manifestOwner, manifestRepo, targetManifestAsset).then(
    async ({ manifestVersion, binaryUrl }) => {
      getCLI(manifestVersion, binaryUrl, manifestBinary).then(async () => {
        generateSBOM(
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
        ).then(async (outputPath) => {
          let updateCommand = `SBOM_FILENAME=${bomFilePath} SBOM_OUTPUT=${output} SBOM_NAME=${name}`;
          if (version?.length > 0) {
            updateCommand = `${updateCommand} SBOM_VERSION=${version}`;
          }
          updateCommand =
            `${updateCommand} bash ${__dirname}/update-sbom.sh`.replace(
              "\n",
              ""
            );
          execWrapper(updateCommand).then(async () => {
            console.log("SBOM Updated");
            if (outputPath && artifact === "true") {
              const upload = await artifactClient.uploadArtifact(
                "sbom",
                [outputPath],
                outputPath.substring(0, outputPath.lastIndexOf("/"))
              );
              core.info(`SBOM uploaded to GitHub as an artifact: ${upload}`);
            }
            if (shouldPublish(apiKey, publish)) {
              let publishCommand = `MANIFEST_API_KEY=${apiKey} ${manifestBinary} publish --ignore-validation="true"  --source="${source}" --relationship="${relationship}" --active="${active}" ${bomFilePath}`;
              const mVer = semver.coerce(manifestVersion);
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
          });
        });
      });
    }
  );
} catch (error) {
  core.setFailed(error.message);
}
