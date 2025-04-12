const fs = require('fs');

const detectionPatterns = {
    explicitIndicators: [
        /h[a@4]ck[e3]d?\b/i,
        /h[a@4]ck[e3]d?\s+by/i,
        /b[a@4]c{k}?[d]{1,2}[o0]{1,3}r+\b/i, 
        /b[a@4]+[ck]+d[o0]+r+/i,             
        /b[._-]?a[._-]?c[._-]?k[._-]?d[._-]?o[._-]?o[._-]?r/i, 
        /m[a@4]l(?:icious|ware)\b/i,
        /eicar[\W_]*standard[\W_]*antivirus[\W_]*test[\W_]*file/i
    ],

    suspiciousPatterns: [
        /\b(?:exec|eval|system|passthru|popen|proc_open|pcntl_exec|assert)\s*\(/i,
        /\b(?:create_function|base64_decode|gzinflate|str_rot13|rawurldecode|unserialize)\s*\(/i,
        /\bpwned\s+by\b/i,
        /\bshell_exec\s*\(/i,
        /\bset_time_limit\s*\(/i,
        /[\$a-z0-9_]{1,20}\s*=\s*base64_decode\s*\(/i,
    ],

    obfuscationPatterns: [
        /\b(?:fromCharCode|charCodeAt|unescape|decodeURIComponent|atob|btoa)\b/i,
        /String\.(?:fromCharCode|prototype)/i,
        /eval\s*\(/i,
        /constructor\s*\(/i,
        /replace\s*\(\s*\/\.\/g\s*/i,
        /function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)/i,
        /\b(?:packer|javascriptobfuscator|obfuscator\.io)\b/i,
        /(?:(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\u[0-9a-fA-F]{4}){2,})/i,
        /\b[a-zA-Z_]{1,10}\s*\+\s*['"][^'"]{1,10}['"]\s*\+\s*[a-zA-Z_]{1,10}/i
    ],

    maliciousHosts: [
        /pastebin\.com/i,
        /malicious\.example/i,
        /anonfiles\.com/i,
        /cdn\.[\w-]+\.(?:ru|tk|cn)/i,
        /(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?/
    ],

    xorEncodedPayloads: [
        /charCodeAt\(\s*i\s*\)\s*\^\s*\d{1,3}/i,
        /for\s*\(\s*var\s*i\s*=\s*0;\s*i\s*<\s*[a-z]+\.(length|size)/i,
        /(?:String\.fromCharCode|eval)\(\s*.+\^\d+\s*\)/i
    ],

    suspiciousVariables: [
        /\b(_0x[a-f0-9]{4,})\b/i,
        /\b(?:tempVar|payload|shellCode|exploit|encoded|obfuscated)\b/i
    ]
};

const filePatterns = [
    /\.js$/i, /\.php$/i, /\.html?$/i,
    /\.jsx$/i, /\.tsx?$/i, /\.phtml$/i,
    /\.inc$/i
];

function calculateSeverity(threats) {
    const highSeverityPatterns = [
        ...detectionPatterns.explicitIndicators,
        ...detectionPatterns.suspiciousPatterns,
        ...detectionPatterns.xorEncodedPayloads,
        ...detectionPatterns.suspiciousVariables
    ];

    const criticalPatterns = [
        /\beval\s*\(/i,
        /\bsystem\s*\(/i,
        /\bshell_exec\s*\(/i,
        /\bbase64_decode\s*\(/i,
        /\bpopen\s*\(/i,
        /\bproc_open\s*\(/i,
        /\bunserialize\s*\(/i
    ];

    if (threats.some(t => criticalPatterns.some(cp =>
        typeof t === 'string' ? cp.test(t) : cp.test(t.pattern)))) {
        return 'critical';
    }

    if (threats.some(t => highSeverityPatterns.some(hp =>
        typeof t === 'string' ? hp.test(t) : hp.test(t.pattern)))) {
        return 'high';
    }

    return 'medium';
}

function calculateThreatScore(threats) {
    if (!threats || threats.length === 0) return 0;

    const threatWeights = {
        critical: 10,
        high: 5,
        medium: 3,
        low: 1,

        explicitIndicators: 8,
        suspiciousPatterns: 6,
        obfuscationPatterns: 4,
        maliciousHosts: 7,
        xorEncodedPayloads: 9,
        suspiciousVariables: 5,

        packed_code_detected: 8,
        long_base64_string_detected: 6,
        excessive_string_concatenation: 4,
        suspicious_url: 5
    };

    let score = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;

    for (const threat of threats) {
        if (typeof threat === 'string') {

            switch (threat) {
                case 'packed_code_detected':
                    score += threatWeights.packed_code_detected;
                    break;
                case 'long_base64_string_detected':
                    score += threatWeights.long_base64_string_detected;
                    break;
                case 'excessive_string_concatenation':
                    score += threatWeights.excessive_string_concatenation;
                    break;
            }
        } else if (threat.type === 'suspicious_url') {
            score += threatWeights.suspicious_url;
        } else {

            const patternStr = threat.pattern || '';

            if (detectionPatterns.explicitIndicators.some(p => p.toString() === patternStr)) {
                score += threatWeights.explicitIndicators;
            } else if (detectionPatterns.suspiciousPatterns.some(p => p.toString() === patternStr)) {
                score += threatWeights.suspiciousPatterns;
            } else if (detectionPatterns.obfuscationPatterns.some(p => p.toString() === patternStr)) {
                score += threatWeights.obfuscationPatterns;
            } else if (detectionPatterns.maliciousHosts.some(p => p.toString() === patternStr)) {
                score += threatWeights.maliciousHosts;
            } else if (detectionPatterns.xorEncodedPayloads.some(p => p.toString() === patternStr)) {
                score += threatWeights.xorEncodedPayloads;
            } else if (detectionPatterns.suspiciousVariables.some(p => p.toString() === patternStr)) {
                score += threatWeights.suspiciousVariables;
            }
        }
    }

    const severity = calculateSeverity(threats);
    switch (severity) {
        case 'critical':
            criticalCount++;
            break;
        case 'high':
            highCount++;
            break;
        case 'medium':
            mediumCount++;
            break;
    }

    score += criticalCount * threatWeights.critical;
    score += highCount * threatWeights.high;
    score += mediumCount * threatWeights.medium;

    score = Math.min(100, Math.round(10 * Math.log1p(score)));

    return score;
}

function performScan(files = [], options = {}) {
    const {
        deepScan = true,
        scanNodeModules = false,
        maxFileSizeMB = 5
    } = options;

    const results = [];
    const filteredFiles = files.filter(file => {
        if (!filePatterns.some(pattern => pattern.test(file))) {
            return false;
        }

        if (!scanNodeModules && /node_modules[\\/]/i.test(file)) {
            return false;
        }

        try {
            const stats = fs.statSync(file);
            return stats.size <= maxFileSizeMB * 1024 * 1024;
        } catch {
            return false;
        }
    });

    for (const file of filteredFiles) {
        try {
            const content = readFileContent(file);
            const threats = scanContent(content, { deepScan });

            if (threats.length > 0) {
                results.push({
                    file: file,
                    threats: [...new Set(threats)],
                    severity: calculateSeverity(threats),
                    threatScore: calculateThreatScore(threats) 
                });
            }
        } catch (error) {
            results.push({
                file: file,
                error: `Error scanning file: ${error.message}`,
                severity: 'warning',
                threatScore: 0
            });
        }
    }

    return results;
}

function scanContent(content, options = { deepScan: true }) {
    const analysisText = [content];

    if (options.deepScan) {
        analysisText.push(...getDeobfuscatedStrings(content));
        analysisText.push(...detectSuspiciousStructures(content));
    }

    const combinedText = analysisText.join('\n');

    return [
        ...detectKeywords(combinedText),
        ...detectSuspiciousURLs(combinedText)
    ];
}

function getDeobfuscatedStrings(content) {
    const decodedStrings = [];

    decodedStrings.push(decodeHex(content));
    decodedStrings.push(decodeURL(content));
    decodedStrings.push(...decodeBase64Strings(content));
    decodedStrings.push(...decodeCharCodeStrings(content));
    decodedStrings.push(...decodeEvalUnescape(content));
    decodedStrings.push(...decodeNestedEncodings(content));

    return decodedStrings.filter(s => s.length > 0);
}

function decodeHex(str) {
    try {
        return str.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
            String.fromCharCode(parseInt(hex, 16)));
    } catch {
        return '';
    }
}

function decodeURL(str) {
    try {
        return decodeURIComponent(str);
    } catch {
        try {
            return str.replace(/%([0-9a-f]{2})/gi, (_, hex) =>
                String.fromCharCode(parseInt(hex, 16)));
        } catch {
            return '';
        }
    }
}

function decodeBase64Strings(str) {
    const base64Regex = /(?:['"])([A-Za-z0-9+/=]{20,})(?:['"])/g;
    const results = [];
    let match;

    while ((match = base64Regex.exec(str)) !== null) {
        try {
            const decoded = Buffer.from(match[1], 'base64').toString();
            if (decoded.length > 3 && /[\x20-\x7E]{4,}/.test(decoded)) {
                results.push(decoded);
            }
        } catch {
            continue;
        }
    }
    return results;
}

function decodeCharCodeStrings(str) {
    const charCodePatterns = [
        /String\.fromCharCode\(\s*([^)]+)\s*\)/g,
        /\.fromCharCode\(\s*([^)]+)\s*\)/g,
        /String\[["']fromCharCode["']\]\(\s*([^)]+)\s*\)/g
    ];

    const results = [];

    for (const pattern of charCodePatterns) {
        let match;
        while ((match = pattern.exec(str)) !== null) {
            try {
                const codes = match[1].split(/\s*,\s*/)
                    .map(n => parseInt(n.trim(), 10))
                    .filter(n => !isNaN(n));

                if (codes.length > 0) {
                    results.push(String.fromCharCode(...codes));
                }
            } catch {
                continue;
            }
        }
    }
    return results;
}

function decodeEvalUnescape(str) {
    const patterns = [
        /eval\(\s*unescape\(\s*['"](.*?)['"]\s*\)\s*\)/g,
        /eval\(\s*decodeURIComponent\(\s*['"](.*?)['"]\s*\)\s*\)/g
    ];

    const results = [];

    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(str)) !== null) {
            try {
                results.push(decodeURIComponent(match[1]));
            } catch {
                try {
                    results.push(unescape(match[1]));
                } catch {
                    continue;
                }
            }
        }
    }
    return results;
}

function decodeNestedEncodings(str) {
    const results = [];
    let currentStr = str;

    for (let i = 0; i < 3; i++) {
        const decodedHex = decodeHex(currentStr);
        const decodedURL = decodeURL(decodedHex);
        const base64Decoded = decodeBase64Strings(decodedURL).join(' ');

        if (decodedHex !== currentStr || decodedURL !== decodedHex || base64Decoded.length > 0) {
            const combined = base64Decoded || decodedURL;
            results.push(combined);
            currentStr = combined;
        } else {
            break;
        }
    }

    return results;
}

function detectKeywords(text) {
    const threats = [];

    for (const pattern of [
        ...detectionPatterns.explicitIndicators,
        ...detectionPatterns.suspiciousPatterns,
        ...detectionPatterns.obfuscationPatterns
    ]) {
        const matches = text.match(pattern) || [];
        for (const match of matches) {
            threats.push({
                pattern: pattern.toString(),
                match: match
            });
        }
    }

    return threats;
}

function detectSuspiciousURLs(text) {
    const urlRegex = /(?:https?:\/\/|www\.)[^\s"'<>{}|\\^[\]]+/gi;
    const urls = text.match(urlRegex) || [];
    const maliciousUrls = [];

    for (const url of urls) {
        for (const hostPattern of detectionPatterns.maliciousHosts) {
            if (hostPattern.test(url)) {
                maliciousUrls.push({
                    type: 'suspicious_url',
                    url: url,
                    matchedPattern: hostPattern.toString()
                });
                break;
            }
        }
    }

    return maliciousUrls;
}

function detectSuspiciousStructures(content) {
    const suspiciousStructures = [];

    const packedCodeRegex = /eval\(\s*function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)/i;
    if (packedCodeRegex.test(content)) {
        suspiciousStructures.push('packed_code_detected');
    }

    const longBase64Regex = /(?:['"])([A-Za-z0-9+/=]{50,})(?:['"])/g;
    if (longBase64Regex.test(content)) {
        suspiciousStructures.push('long_base64_string_detected');
    }

    const concatRegex = /(["'])\s*\+\s*\1/g;
    const concatMatches = content.match(concatRegex) || [];
    if (concatMatches.length > 10) {
        suspiciousStructures.push('excessive_string_concatenation');
    }

    return suspiciousStructures;
}

function readFileContent(filePath) {
    return fs.readFileSync(filePath, 'utf-8');
}

module.exports = {
    performScan,
    scanContent,
    detectionPatterns,
    calculateSeverity,
    calculateThreatScore
};