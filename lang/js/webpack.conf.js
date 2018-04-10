const path = require('path');

module.exports = {
  entry: './src/index.js',
  // mode: 'development',
  mode: 'production',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'gpgmejs.bundle.js',
    libraryTarget: 'var',
    library: 'Gpgmejs'
  }
};
