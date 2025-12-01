// Vue.js component that should NOT trigger HIGH RISK alerts
import { createApp } from 'vue'

const isDev = process.env.NODE_ENV !== 'production'
const apiUrl = process.env.VUE_APP_API_URL || 'http://localhost:3000'

export default {
  name: 'SearchComponent',
  data() {
    return {
      searchTerm: '',
      results: [],
      isLoading: false
    }
  },
  methods: {
    async performSearch() {
      this.isLoading = true
      try {
        // This should NOT be flagged as suspicious
        const response = await fetch(`${apiUrl}/search?q=${this.searchTerm}`)
        this.results = await response.json()

        if (isDev) {
          console.log('Search results:', this.results)
        }

        // Collect and organize results for display
        this.organizeResults()
      } catch (error) {
        console.error('Search failed:', error)
      } finally {
        this.isLoading = false
      }
    },

    organizeResults() {
      // This contains "collect" but is legitimate
      this.results = this.results.filter(item => item.active)
    }
  }
}