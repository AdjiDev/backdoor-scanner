const scanner = require('./lib/scanner');

module.exports = {
    scanFiles: scanner.performScan,
    scanContent: scanner.scanContent,
    patterns: scanner.detectionPatterns,
    calculateSeverity: scanner.calculateSeverity,
    calculateThreatScore: scanner.calculateThreatScore
};