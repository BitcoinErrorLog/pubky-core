#!/bin/bash
set -e

echo "Building pubky-sdk for Android..."

# Android targets
TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "i686-linux-android"
    "x86_64-linux-android"
)

# Build for each target
for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    cargo build --release --target $target --features uniffi_macros,json
done

# Create output directory
mkdir -p platforms/android/jniLibs

# Create jniLibs directories
mkdir -p platforms/android/jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64}

# Copy libraries to jniLibs structure
cp target/aarch64-linux-android/release/libpubky.so platforms/android/jniLibs/arm64-v8a/libpubky_sdk.so
cp target/armv7-linux-androideabi/release/libpubky.so platforms/android/jniLibs/armeabi-v7a/libpubky_sdk.so
cp target/i686-linux-android/release/libpubky.so platforms/android/jniLibs/x86/libpubky_sdk.so
cp target/x86_64-linux-android/release/libpubky.so platforms/android/jniLibs/x86_64/libpubky_sdk.so

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
mkdir -p platforms/android/kotlin
cargo run --bin uniffi-bindgen --features bindgen-cli --release -- kotlin platforms/android/kotlin

echo "✓ Android build complete!"
echo "  Libraries: platforms/android/jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64}/"
echo "  Bindings: platforms/android/kotlin/"

