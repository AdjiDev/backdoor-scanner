const { scanFiles } = require('backdoor-scanner');

const res = scanFiles(['target.js'], {
  deepScan: true,
  scanNodeModules: false,
  maxFileSizeMB: 5
});

console.log(JSON.stringify(res, null, 2))