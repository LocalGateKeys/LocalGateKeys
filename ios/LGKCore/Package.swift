// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "LGKCore",
    // English source text; Sources/LGKCore/Resources/Localizable.xcstrings holds the translations (bundle: .module).
    defaultLocalization: "en",
    // watchOS: the Apple Watch app (UX workstream 12) uses TOTP and WatchMessage only.
    platforms: [.iOS(.v17), .macOS(.v14), .watchOS(.v10)],
    products: [.library(name: "LGKCore", targets: ["LGKCore"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "CArgon2", path: "Sources/CArgon2", publicHeadersPath: "include"),
        .target(
            name: "LGKCore",
            dependencies: [
                "CArgon2", .product(name: "Crypto", package: "swift-crypto"),
                // AES-CBC and PBKDF2 where CommonCrypto is missing (Apple platforms use CommonCrypto).
                .product(name: "_CryptoExtras", package: "swift-crypto", condition: .when(platforms: [.linux, .windows, .android])),
            ],
            resources: [.process("Resources")]
        ),
        .testTarget(name: "LGKCoreTests", dependencies: ["LGKCore"]),
    ],
    swiftLanguageModes: [.v6]
)
