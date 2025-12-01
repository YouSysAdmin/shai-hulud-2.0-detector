// Legitimate HTTP client - should NOT trigger XMLHttpRequest detection
class HttpClient {
    constructor() {
        this.defaultHeaders = {
            'Content-Type': 'application/json'
        };
    }

    // Normal XMLHttpRequest usage - should not trigger
    makeRequest(url, data) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', url);

            Object.keys(this.defaultHeaders).forEach(key => {
                xhr.setRequestHeader(key, this.defaultHeaders[key]);
            });

            xhr.onload = () => {
                if (xhr.status === 200) {
                    resolve(JSON.parse(xhr.responseText));
                } else {
                    reject(new Error(`Request failed: ${xhr.status}`));
                }
            };

            xhr.send(JSON.stringify(data));
        });
    }

    // Legitimate fetch wrapper
    async fetchData(endpoint) {
        const response = await fetch(endpoint);
        return await response.json();
    }
}