#!/bin/bash
set -e

echo "Building pubky-sdk for iOS..."

# Build for iOS targets
echo "Building for aarch64-apple-ios (device)..."
cargo build --release --target aarch64-apple-ios --features uniffi_macros,json

echo "Building for aarch64-apple-ios-sim (simulator ARM)..."
cargo build --release --target aarch64-apple-ios-sim --features uniffi_macros,json

echo "Building for x86_64-apple-ios (simulator Intel)..."
cargo build --release --target x86_64-apple-ios --features uniffi_macros,json

# Create output directory
mkdir -p platforms/ios

# Create universal simulator library
echo "Creating universal simulator library..."
lipo -create \
    target/aarch64-apple-ios-sim/release/libpubky.a \
    target/x86_64-apple-ios/release/libpubky.a \
    -output platforms/ios/libpubky_sdk-sim.a

# Copy device library
cp target/aarch64-apple-ios/release/libpubky.a platforms/ios/libpubky_sdk-device.a

# Generate Swift bindings
echo "Generating Swift bindings..."
mkdir -p platforms/ios
cargo run --bin uniffi-bindgen --features bindgen-cli --release -- swift platforms/ios

# Create modulemap for C headers  
cat > platforms/ios/module.modulemap << EOF
module PubkySDKFFI {
    header "pubky_sdkFFI.h"
    export *
}
EOF

# Create XCFramework
echo "Creating XCFramework..."
rm -rf platforms/ios/PubkySDK.xcframework

xcodebuild -create-xcframework \
    -library platforms/ios/libpubky_sdk-device.a \
    -headers platforms/ios \
    -library platforms/ios/libpubky_sdk-sim.a \
    -headers platforms/ios \
    -output platforms/ios/PubkySDK.xcframework

echo "✓ iOS build complete!"
echo "  Framework: platforms/ios/PubkySDK.xcframework"
echo "  Swift bindings: platforms/ios/pubky_sdk.swift"
echo "  C headers: platforms/ios/pubky_sdkFFI.h"

