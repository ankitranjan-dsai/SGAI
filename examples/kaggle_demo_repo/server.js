// ⚠️ INTENTIONALLY INSECURE JavaScript — a target for SGAI's --deep (Semgrep)
// multi-language static analysis. Demo fixture only; do NOT ship this.
const { exec } = require("child_process");
const http = require("http");

http
  .createServer((req, res) => {
    const cmd = new URL(req.url, "http://x").searchParams.get("cmd");

    // Semgrep flags eval() on request-derived input as code injection.
    const result = eval(cmd);

    // Semgrep flags child_process.exec with concatenated input (command injection).
    exec("echo " + cmd, (err, stdout) => res.end(String(result) + stdout));
  })
  .listen(3000);
