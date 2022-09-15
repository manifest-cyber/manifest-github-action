const fs = require("fs");
const https = require("https");
const core = require("@actions/core");

try {
  const apiKey = core.getInput("apiKey");
  const bomFilePath = core.getInput("bomFilePath");

  const bomContents = fs.readFileSync(bomFilePath);
  const base64BomContents = Buffer.from(bomContents).toString("base64");

  const payload = {
    apiKey,
    base64BomContents,
  };

  const postData = JSON.stringify(payload);

  const requestOptions = {
    hostname: "mvdryhw7l8.execute-api.us-east-1.amazonaws.com",
    path: "/prod/receive/",
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
  };

  console.log("Sending request to Manifest Server");

  const req = https.request(requestOptions, (res) => {
    const statusCode = res.statusCode;
    if (statusCode >= 200 && statusCode < 300) {
      console.log("Uploaded to Manifest Server");
    } else {
      core.setFailed(
        "Failed to upload:" + res.statusCode + " " + res.statusMessage
      );
    }
  });

  req.on("error", (e) => {
    console.error(`Problem with request: ${e.message}`);
    core.setFailed(e.message);
  });

  req.write(postData);
  req.end();
} catch (error) {
  core.setFailed(error.message);
}
