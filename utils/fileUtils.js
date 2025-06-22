const fs = require("fs");
const path = require("path");

function readSolidityFile(filePath) {
    try {
        return fs.readFileSync(filePath, "utf8");
    } catch (err) {
        console.error("❌ Error reading file:", err.message);
        return null;
    }
}

function writeSolidityFile(filePath, content) {
    try {
        fs.writeFileSync(filePath, content, "utf8");
        console.log("✅ Fixed code saved to:", filePath);
    } catch (err) {
        console.error("❌ Error writing file:", err.message);
    }
}

module.exports = {
    readSolidityFile,
    writeSolidityFile,
};
