// File: detectors/dos.js

/**
 * Detects Denial-of-Service (DoS) with external call vulnerabilities.
 * Focus: External calls inside loops (e.g. for/while), which can be gas-heavy and block execution.
 */
const detectDoS = (code, filename = "input.sol") => {
    const lines = code.split("\n");
    const vulnerabilities = [];
    const modifiedLines = [...lines];

    const loopStartPattern = /(for\s*\(|while\s*\()/;
    const externalCallPattern = /[^\/\n]*\.(call|send|transfer)\s*(\{[^}]*\})?\s*\(/;

    let inLoop = false;
    let loopStartLine = -1;
    let braceDepth = 0;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (loopStartPattern.test(line)) {
            inLoop = true;
            loopStartLine = i;
        }

        if (inLoop) {
            braceDepth += (line.match(/{/g) || []).length;
            braceDepth -= (line.match(/}/g) || []).length;

            if (externalCallPattern.test(line) && !line.includes("// WARNING: DoS risk")) {
                vulnerabilities.push({
                    line: i + 1,
                    loopLine: loopStartLine + 1,
                    original: line.trim(),
                    detail: "External call inside loop may cause DoS (Denial-of-Service)"
                });
                modifiedLines[i] = `// WARNING: DoS risk - consider redesigning loop\n` + modifiedLines[i];
            }

            if (braceDepth <= 0) {
                inLoop = false;
                loopStartLine = -1;
            }
        }
    }

    return {
        modifiedCode: modifiedLines.join("\n"),
        vulnerabilities
    };
};

module.exports = { detectDoS };
