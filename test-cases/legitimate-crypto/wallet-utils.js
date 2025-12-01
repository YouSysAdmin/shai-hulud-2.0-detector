// Legitimate wallet utilities - should NOT trigger crypto theft detection
const ethers = require('ethers');

class WalletManager {
    constructor() {
        // Example legitimate ethereum address for documentation
        this.exampleAddress = "0x742d35Cc6634C0532925a3b8D84C1AFf3f8ca3BC";
    }

    validateEthereumAddress(address) {
        // Legitimate address validation
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    }

    async sendTransaction(to, amount) {
        // Legitimate transaction sending
        const provider = new ethers.JsonRpcProvider();
        const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

        return await wallet.sendTransaction({
            to: to,
            value: ethers.parseEther(amount.toString())
        });
    }

    // Legitimate API call using fetch
    async getBalance(address) {
        const response = await fetch(`https://api.etherscan.io/api?module=account&action=balance&address=${address}`);
        return await response.json();
    }
}