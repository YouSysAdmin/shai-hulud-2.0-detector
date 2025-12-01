// Common HTTP request patterns - should NOT trigger HIGH RISK
const axios = require('axios');

class ApiClient {
    constructor() {
        this.baseURL = 'https://api.etherscan.io';
    }

    // Standard XMLHttpRequest usage (not prototype hijacking)
    makeXhrRequest(url, data) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', url);
            xhr.setRequestHeader('Content-Type', 'application/json');

            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    if (xhr.status === 200) {
                        resolve(JSON.parse(xhr.responseText));
                    } else {
                        reject(new Error(`Request failed: ${xhr.status}`));
                    }
                }
            };

            xhr.send(JSON.stringify(data));
        });
    }

    // Standard fetch usage
    async fetchData(endpoint) {
        try {
            const response = await fetch(`${this.baseURL}${endpoint}`);
            return await response.json();
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    }

    // Axios usage
    async getBalance(address) {
        const response = await axios.get(`${this.baseURL}/api`, {
            params: {
                module: 'account',
                action: 'balance',
                address: address,
                tag: 'latest'
            }
        });
        return response.data;
    }
}

module.exports = { ApiClient };