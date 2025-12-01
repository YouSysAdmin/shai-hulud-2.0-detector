// Webpack configuration that legitimately uses environment variables
const path = require('path')

module.exports = {
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js'
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.API_URL': JSON.stringify(process.env.API_URL),
      'process.env.AWS_REGION': JSON.stringify(process.env.AWS_REGION),
      'process.env.GITHUB_TOKEN': JSON.stringify(process.env.GITHUB_TOKEN)
    })
  ],
  devServer: {
    port: process.env.PORT || 8080,
    // This searches for available ports but is legitimate
    host: process.env.HOST || 'localhost'
  }
}