// Express.js server that legitimately uses environment variables
const express = require('express')
const app = express()

// Standard environment variable usage - should NOT be HIGH RISK
const port = process.env.PORT || 3000
const dbUrl = process.env.DATABASE_URL
const apiKey = process.env.API_KEY

// JWT secret from environment
const jwtSecret = process.env.JWT_SECRET || 'default-secret'

// AWS configuration
const awsConfig = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1'
}

app.get('/search', (req, res) => {
  // This contains "search" but is a legitimate API endpoint
  const query = req.query.q

  // Collect search parameters
  const searchParams = {
    query,
    limit: req.query.limit || 10,
    offset: req.query.offset || 0
  }

  res.json({ message: 'Search endpoint', params: searchParams })
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
  if (process.env.NODE_ENV === 'development') {
    console.log('Development mode enabled')
  }
})