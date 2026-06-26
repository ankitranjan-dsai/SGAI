// Intentionally unsafe JS, for SGAI's multi-language (Semgrep) analysis.
function run(userInput) {
  // Arbitrary code execution via eval on untrusted input.
  return eval(userInput);
}

module.exports = { run };
