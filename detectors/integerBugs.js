// File: detectors/integerBugs.js

const detectIntegerBugs = (code, filename = "input.sol") => {
    const lines = code.split("\n");
    const vulnerabilities = [];
    const modifiedLines = [...lines];

    const arithmeticPattern = /([\w\[\]\.]*)\s*(\+=|-=|\*=|\/=|=\s*\1\s*[+\-*/])/;

    let insideUnchecked = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Track unchecked block context
        if (line.startsWith("unchecked {")) {
            insideUnchecked = true;
        }
        if (insideUnchecked && line.includes("}")) {
            insideUnchecked = false;
        }

        if (arithmeticPattern.test(line) && !insideUnchecked) {
            if (!line.includes("SafeMath")) {
                vulnerabilities.push({
                    line: i + 1,
                    original: lines[i].trim(),
                    detail: "Potential overflow/underflow: consider using 'unchecked' or Solidity's checked math."
                });

                // Wrap in unchecked block only if not already inside one
                modifiedLines[i] = `unchecked { ${lines[i].trim()} }`;
            }
        }
    }

    return {
        modifiedCode: modifiedLines.join("\n"),
        vulnerabilities
    };
};

module.exports = { detectIntegerBugs };
