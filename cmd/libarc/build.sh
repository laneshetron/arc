#!/usr/bin/env bash
# build.sh OUT: builds libarc as static archives and an xcframework in OUT.
#
#   OUT/macos/libarc.a           macOS arm64 and x86_64
#   OUT/ios/libarc.a             iOS arm64
#   OUT/ios-simulator/libarc.a   iOS simulator arm64
#   OUT/include/                 arc.h and module.modulemap
#   OUT/libarc.xcframework       all three, for Xcode
#
# Needs Go and Xcode. MACOS_MIN and IOS_MIN set the deployment targets.
set -euo pipefail
out=$(mkdir -p "${1:?usage: build.sh OUT}" && cd "$1" && pwd)
cd "$(dirname "$0")/../.."
macos_min=${MACOS_MIN:-12.0} ios_min=${IOS_MIN:-15.0}

slice() { # slice GOOS GOARCH SDK TARGET OUTFILE
  local sdk_path
  sdk_path=$(xcrun --sdk "$3" --show-sdk-path)
  CGO_ENABLED=1 GOOS=$1 GOARCH=$2 CC="$(xcrun --sdk "$3" -f clang)" \
    CGO_CFLAGS="-isysroot $sdk_path -target $4" CGO_LDFLAGS="-isysroot $sdk_path -target $4" \
    go build -buildmode=c-archive -trimpath -o "$5" ./cmd/libarc
  rm -f "${5%.a}.h" # cgo's header; arc.h is the interface
}

rm -rf "$out"/{macos,ios,ios-simulator,include,libarc.xcframework,tmp}
mkdir -p "$out"/{macos,ios,ios-simulator,tmp}
slice darwin arm64 macosx "arm64-apple-macos$macos_min" "$out/tmp/macos-arm64.a"
slice darwin amd64 macosx "x86_64-apple-macos$macos_min" "$out/tmp/macos-amd64.a"
lipo -create -output "$out/macos/libarc.a" "$out/tmp/macos-arm64.a" "$out/tmp/macos-amd64.a"
slice ios arm64 iphoneos "arm64-apple-ios$ios_min" "$out/ios/libarc.a"
slice ios arm64 iphonesimulator "arm64-apple-ios$ios_min-simulator" "$out/ios-simulator/libarc.a"
rm -rf "$out/tmp"
cp -R cmd/libarc/include "$out/include"
xcodebuild -create-xcframework -output "$out/libarc.xcframework" \
  -library "$out/macos/libarc.a" -headers "$out/include" \
  -library "$out/ios/libarc.a" -headers "$out/include" \
  -library "$out/ios-simulator/libarc.a" -headers "$out/include" >/dev/null
echo "libarc built in $out"
