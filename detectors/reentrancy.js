
const fs = require("fs");

const riskyPatterns = [/\.call\s*\{/, /\.send\s*\(/, /\.transfer\s*\(/];

function isExternalCall(line) {
    return riskyPatterns.some((pattern) => pattern.test(line));
}

function isStateUpdate(line) {
    return line.includes("= 0") || line.match(/\w+\[.*\]\s*=\s*0/);
}

function isProtectedFunctionHeader(headerLine) {
    return headerLine.includes("noReentrant");
}

function getFunctionVisibility(headerLine) {
    if (headerLine.includes("internal")) return "internal";
    if (headerLine.includes("private")) return "private";
    if (headerLine.includes("external")) return "external";
    return "public"; // default
}

function detectAndFixReentrancy(code, fileName = "input.sol") {
    const lines = code.split("\n");

    const functions = {};
    const callGraph = {};
    const vulnerabilities = [];
    const visited = new Set();

    // Step 1: Extract all functions
    let inFunction = false;
    let braceCount = 0;
    let currentFunction = null;

    lines.forEach((line, index) => {
        const headerMatch = line.match(/function\s+(\w+)\s*\([^)]*\).*\{?/);
        if (headerMatch) {
            inFunction = true;
            braceCount = (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
            currentFunction = {
                name: headerMatch[1],
                start: index,
                headerLine: line,
                end: index,
                visibility: getFunctionVisibility(line),
            };
        } else if (inFunction) {
            braceCount += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
            if (braceCount === 0) {
                currentFunction.end = index;
                functions[currentFunction.name] = { ...currentFunction };
                inFunction = false;
            }
        }
    });

    // Step 2: Build call graph
    for (const [name, func] of Object.entries(functions)) {
        callGraph[name] = new Set();
        for (let i = func.start; i <= func.end; i++) {
            const callMatch = lines[i].match(/(\w+)\s*\(/);
            if (callMatch && callMatch[1] !== name && functions[callMatch[1]]) {
                callGraph[name].add(callMatch[1]);
            }
        }
    }

    function analyzeFunction(name, ancestors = []) {
        if (visited.has(name)) return false;
        visited.add(name);

        const func = functions[name];
        let seenStateUpdate = false;
        let isVulnerable = false;

        for (let i = func.start; i <= func.end; i++) {
            if (isStateUpdate(lines[i])) seenStateUpdate = true;
            if (isExternalCall(lines[i]) && !seenStateUpdate) {
                isVulnerable = true;
                break;
            }

            const callMatch = lines[i].match(/(\w+)\s*\(/);
            if (callMatch && callGraph[name].has(callMatch[1])) {
                if (analyzeFunction(callMatch[1], [...ancestors, name])) {
                    isVulnerable = true;
                    break;
                }
            }
        }

        return isVulnerable;
    }

    for (const [name, func] of Object.entries(functions)) {
        visited.clear();
        const shouldInject =
            !isProtectedFunctionHeader(func.headerLine) &&
            analyzeFunction(name) &&
            func.visibility !== "internal" &&
            func.visibility !== "private";

        if (shouldInject) {
            vulnerabilities.push({
                name,
                startLine: func.start,
                functionHeader: func.headerLine.trim(),
                line: func.start + 1,
                detail: "Uses risky external call before state update (.call, .send, or .transfer)",
            });
        }
    }

    // Step 4: Inject modifier and fix
    const outputLines = [...lines];
    const insertedModifier = `\n    modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }\n`;

    const contractIndex = outputLines.findIndex((line) => line.includes("contract "));
    if (!outputLines.some((line) => line.includes("modifier noReentrant"))) {
        outputLines.splice(contractIndex + 1, 0, "    bool private locked;" + insertedModifier);
    }

    for (const vuln of vulnerabilities) {
        for (let i = vuln.startLine; i < outputLines.length; i++) {
            if (outputLines[i].includes("function") && outputLines[i].includes(vuln.name)) {
                const funcRegex = /(function\s+\w+\s*\([^)]*\)\s*(public|external|internal|private)?\s*)/;
                if (funcRegex.test(outputLines[i])) {
                    outputLines[i] = outputLines[i].replace(funcRegex, (match, p1) => {
                        return `${p1.trim()} noReentrant `;
                    });
                    break;
                }
            }
        }
    }

    return {
        modifiedCode: outputLines.join("\n"),
        vulnerabilities
    };
}

module.exports = { detectAndFixReentrancy };
