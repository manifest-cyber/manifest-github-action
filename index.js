const fs = require("fs");
const https = require("https");
const http = require("http");
const core = require("@actions/core");
const path = require('path');
const { exec } = require("child_process");
const util = require("node:util");

const execPromise = util.promisify(exec);

async function execWrapper(cmd) {
  const { stdout, stderr, error } = await execPromise(cmd);
  if (stdout) {
    console.log(`stdout: ${stdout}`);
  }

  if (stderr) {
    console.log(`stderr: ${stdout}`);
    return;
  }

  if (error) {
    core.setFailed(`error: ${error}`);
    return;
  }
}

try {
  const apiKey = core.getInput("apiKey");
  console.log("apikey", apiKey)
  const bomFilePath = core.getInput("bomFilePath");
  const output = core.getInput("sbom-output");
  const name = core.getInput("sbom-name");
  const version = core.getInput("sbom-version");

  const relationship = core.getInput("relationship");
  const source = core.getInput("source");

  execWrapper(`SBOM_FILENAME=${bomFilePath} SBOM_OUTPUT=${output} SBOM_NAME=${name} SBOM_VERSION=${version} bash ./update-sbom.sh`).then(() => {
    const bomContents = fs.readFileSync(bomFilePath);
    const base64BomContents = Buffer.from(bomContents).toString("base64");

    const payload = {
      base64BomContents, // Incoming file Buffer
      relationship,// 'first' or 'third'-party
      filename: bomFilePath, // File name/path. Optional. Used for logging/debugging purposes.
      source, // This is stored and visible to you in the Manifest app.
    };

    const postData = JSON.stringify(payload);

    const requestOptions = {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(postData),
      },
    };

    console.log("Sending request to Manifest Server");
    let req = null;

    /**
     * At Manifest, we like to eat our own dogfood - you'll see some development code we use when testing our API and this action locally. You can safely ignore the below `if` statement - the `else` clause will always fire during normal production use of this action. We include our development code for both transparency to you and our own convenience.
     * If you have a better idea or suggested improvements, fork/PR or ping us at engineering@manifestcyber.com and we'd love to chat over a virtual cup of coffee :)
     */
    if (process.env.TEST_LOCALLY && process.env.TEST_LOCALLY === 'enabled') {
      req = http.request(`http://local.manifestcyber.com:8081/v1/sbom/upload`, requestOptions, (res) => {
        const statusCode = res.statusCode;
        if (statusCode >= 200 && statusCode < 300) {
          console.log("[DEV] Uploaded to Manifest Server");
        } else {
          core.setFailed(
            "[DEV] Failed to upload:" + res.statusCode + " " + res.statusMessage
          );
        }
      });
    }

    else {
      req = https.request(`https://api.manifestcyber.com/v1/sbom/upload`, requestOptions, (res) => {
        const statusCode = res.statusCode;
        if (statusCode >= 200 && statusCode < 300) {
          console.log("Uploaded to Manifest Server");
        } else {
          core.setFailed(
            "Failed to upload:" + res.statusCode + " " + res.statusMessage
          );
        }
      });
    }

    req.on("error", (e) => {
      console.error(`Problem with request: ${e.message}`);
      core.setFailed(e.message);
    });

    req.write(postData);
    req.end();
  })
}
catch (error) {
  core.setFailed(error.message);
}

