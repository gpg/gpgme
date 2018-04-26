#/!bin/bash

npx webpack --config webpack.conf.js
mkdir -p BrowserTestExtension/libs
cp node_modules/chai/chai.js \
    node_modules/mocha/mocha.css \
    node_modules/mocha/mocha.js \
    build/gpgmejs.bundle.js BrowserTestExtension/libs
mkdir -p build/extensions
zip -r build/extensions/browsertest.zip BrowserTestExtension

mkdir -p DemoExtension/libs
cp build/gpgmejs.bundle.js DemoExtension/libs
zip -r build/extensions/demoextension.zip DemoExtension
