const core = require("@actions/core");
const cache = require("@actions/tool-cache");
const { exec } = require("child_process");
const util = require("node:util");

const { Octokit } = require("@octokit/rest");
const octokit = new Octokit();
const owner = "manifest-cyber";
const repo = "cli";
const manifestBinary = "manifest";
const binaryPath = `${__dirname}/${manifestBinary}`;

const execPromise = util.promisify(exec);

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

async function getReleaseVersion() {
  // Pull the latest version of the CLI
  let release = await octokit.repos.getLatestRelease({ owner, repo });

  // TODO: Add better support for different platforms
  let targetAsset = "manifest_linux_x86_64.tar.gz";
  const localTest = process.env.TEST_LOCALLY;
  if (localTest && localTest === 'enabled') {
    targetAsset = "manifest_darwin_x86_64.tar.gz";
  }

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

async function getCLI(version, url) {
  // TODO: Add support for caching the CLI
  const tarPath = await cache.downloadTool(url);
  const binaryExtractedPath = await cache.extractTar(tarPath, binaryPath, 'xz');
  core.addPath(binaryExtractedPath)
}

try {
  const apiKey = core.getInput("apiKey");
  core.setSecret(apiKey);
  const bomFilePath = core.getInput("bomFilePath");
  const output = core.getInput("sbom-output");
  const name = core.getInput("sbom-name");
  const version = core.getInput("sbom-version");
  const publish = core.getInput("sbom-publish");
  const generator = core.getInput("sbom-generator");
  const generatorFlags = core.getInput("sbom-generator-flags");

  execWrapper(`SBOM_FILENAME=${bomFilePath} SBOM_OUTPUT=${output} SBOM_NAME=${name} SBOM_VERSION=${version} bash ${__dirname}/update-sbom.sh`).then(async () => {
    /**
     * At Manifest, we like to eat our own dogfood - you'll see some development code we use when testing our API and this action locally. You can safely ignore the below `if` statement - the `else` clause will always fire during normal production use of this action. We include our development code for both transparency to you and our own convenience.
     * If you have a better idea or suggested improvements, fork/PR or ping us at engineering@manifestcyber.com and we'd love to chat over a virtual cup of coffee :)
     */
    // TODO: Add support for running the CLI against a local deployment
    console.log("SBOM Updated");
    const { manifestVersion, binaryUrl } = await getReleaseVersion();
    await getCLI(manifestVersion, binaryUrl);
    core.info("Sending request to Manifest Server");
    execWrapper(`MANIFEST_API_KEY=${apiKey} ${manifestBinary} publish --ignore-validation=True --paths=${bomFilePath}`).then(r => {
      core.info(`Manifest CLI response: ${r}`)
    });
  });
}
catch (error) {
  core.setFailed(error.message);
}

