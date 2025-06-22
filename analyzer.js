const fs = require("fs");
const path = require("path");
const chalk = require("chalk");

const { detectAndFixReentrancy } = require("./detectors/reentrancy");
const { detectIntegerBugs } = require("./detectors/integerBugs");
const { detectDoS } = require("./detectors/dos");

const INPUT_FILE = "input.sol";
const OUTPUT_FILE = "output.sol";

console.log(chalk.blue.bold("\n🔍 Solidity Analyzer Starting...\n"));

try {
    const originalCode = fs.readFileSync(INPUT_FILE, "utf-8");

    // === 1. Reentrancy Detection ===
    console.log(chalk.blue("\n🔎 Checking for Re-Entrancy Vulnerabilities...\n"));
    const {
        modifiedCode: reentrancyFixedCode,
        vulnerabilities: reentrancyIssues,
    } = detectAndFixReentrancy(originalCode);

    if (reentrancyIssues.length > 0) {
        console.log(chalk.red.bold(`🚨 Re-Entrancy Issues Found:\n`));
        reentrancyIssues.forEach((vuln, idx) => {
            const functionName = vuln.functionHeader.split("(")[0].replace("function", "").trim();
            console.log(
                `${chalk.yellow(`${idx + 1}. Function: ${chalk.cyan(functionName)}`)}\n` +
                `   📍 Line: ${chalk.green(vuln.line)}\n` +
                `   💡 Detail: ${chalk.white(vuln.detail)}\n`
            );
        });
        console.log(chalk.blue(" All vulnerable functions will be patched with 'noReentrant' modifier.\n"));
    } else {
        console.log(chalk.green("✅ No re-entrancy vulnerabilities found.\n"));
    }

    // === 2. Integer Bugs Detection ===
    console.log(chalk.blue("\n🔎 Checking for Integer Overflow/Underflow...\n"));
    const {
        modifiedCode: integerFixedCode,
        vulnerabilities: integerIssues,
    } = detectIntegerBugs(reentrancyFixedCode);

    if (integerIssues.length > 0) {
        console.log(chalk.red.bold(`🚨 Integer Issues Found:\n`));
        integerIssues.forEach((vuln, idx) => {
            console.log(
                `${chalk.yellow(`${idx + 1}. Line ${chalk.green(vuln.line)}`)}\n` +
                `   🔍 Code: ${chalk.cyan(vuln.original)}\n` +
                `   💡 Detail: ${chalk.white(vuln.detail)}\n`
            );
        });
        console.log(chalk.blue(" Integer operations have been wrapped in 'unchecked { ... }' blocks.\n"));
    } else {
        console.log(chalk.green("✅ No integer overflow/underflow vulnerabilities found.\n"));
    }

    // === 3. DoS Detection ===
    console.log(chalk.blue("\n🔎 Checking for DoS (Denial-of-Service) Issues...\n"));
    const {
        modifiedCode: dosFixedCode,
        vulnerabilities: dosIssues,
    } = detectDoS(integerFixedCode);

    if (dosIssues.length > 0) {
        console.log(chalk.red.bold(`🚨 DoS Issues Found:\n`));
        dosIssues.forEach((vuln, idx) => {
            console.log(
                `${chalk.yellow(`${idx + 1}. Line ${chalk.green(vuln.line)}`)}\n` +
                `   🔍 Code: ${chalk.cyan(vuln.original)}\n` +
                `   💡 Detail: ${chalk.white(vuln.detail)} (inside loop at line ${chalk.magenta(vuln.loopLine)})\n`
            );
        });
        console.log(chalk.blue("💡 Comments added above external calls in loops to indicate DoS risk.\n"));
    } else {
        console.log(chalk.green("✅ No DoS risks detected in loops.\n"));
    }

    // === Write Final Fixed Output File ===
    fs.writeFileSync(OUTPUT_FILE, dosFixedCode, "utf-8");
    console.log(chalk.green.bold(`✅ Final fixed code saved to: ${path.resolve(OUTPUT_FILE)}\n`));

    // === Summary Footer ===
    console.log(chalk.bgGreen.black("✔ Static Analysis Complete ✔\n"));
} catch (err) {
    console.error(chalk.red("❌ Error during analysis:"), err.message);
}
