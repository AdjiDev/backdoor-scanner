const { scanFiles } = require('@adjidev/backdoor-scanner');

const res = scanFiles(['case.js'], {
  deepScan: true,
  scanNodeModules: false,
  maxFileSizeMB: 5
});

console.log(JSON.stringify(res, null, 2))