// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "LGKCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "LGKCore", targets: ["LGKCore"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "CArgon2", path: "Sources/CArgon2", publicHeadersPath: "include"),
        .target(name: "LGKCore", dependencies: ["CArgon2", .product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "LGKCoreTests", dependencies: ["LGKCore"]),
    ],
    swiftLanguageModes: [.v6]
)
