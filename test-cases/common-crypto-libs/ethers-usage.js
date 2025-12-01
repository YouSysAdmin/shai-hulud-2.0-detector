// Common ethers.js usage patterns - should NOT trigger HIGH RISK
const { ethers } = require('ethers');

async function setupWallet() {
    // Standard ethers.js patterns
    const provider = new ethers.JsonRpcProvider('https://mainnet.infura.io/v3/YOUR-PROJECT-ID');
    const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

    // Example addresses for testing - these are common test addresses
    const testAddresses = [
        '0x742d35Cc6634C0532925a3b8D84C1AFf3f8ca3BC', // Common test address
        '0x8ba1f109551bD432803012645Hac136c44661c93',  // Another test address
    ];

    // Standard address validation
    function isValidAddress(address) {
        return ethers.isAddress(address);
    }

    // Normal transaction sending
    async function sendTransaction(to, amount) {
        const tx = {
            to: to,
            value: ethers.parseEther(amount),
            gasLimit: 21000,
        };

        return await wallet.sendTransaction(tx);
    }

    return { wallet, provider, testAddresses, isValidAddress, sendTransaction };
}

module.exports = { setupWallet };