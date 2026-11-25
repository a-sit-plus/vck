// swift-tools-version: 5.9

import Foundation
import PackageDescription

// Swift package for iOS apps: the `vck-ios` Gradle module, built as `VckIos.xcframework`, bundling all VC-K modules.
// The "Publish Swift Package" workflow uploads the XCFramework to the GitHub release and sets both values below.
let releaseVersion = "0.0.0"
let releaseChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

// Local development: after `./gradlew :vck-ios:assembleVckIosDebugXCFramework`, an app that adds this checkout as a
// local package uses that build instead of the release. Packages resolved from Git never contain `build/`.
let localXCFramework = "vck-ios/build/XCFrameworks/debug/VckIos.xcframework"
let useLocalXCFramework = FileManager.default.fileExists(atPath: "\(Context.packageDirectory)/\(localXCFramework)")

let package = Package(
    name: "vck",
    platforms: [
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "VckIos",
            targets: ["VckIos"]
        )
    ],
    targets: [
        useLocalXCFramework
            ? .binaryTarget(
                name: "VckIos",
                path: localXCFramework
            )
            : .binaryTarget(
                name: "VckIos",
                url: "https://github.com/a-sit-plus/vck/releases/download/\(releaseVersion)/VckIos.xcframework.zip",
                checksum: releaseChecksum
            )
    ]
)
