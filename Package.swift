// swift-tools-version: 6.2
import PackageDescription

let package = Package(
  name: "keylet", platforms: [.macOS("26.4")],
  products: [.executable(name: "keylet", targets: ["keylet"])],
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2")
  ],
  targets: [
    .systemLibrary(name: "CSQLite"),
    .target(name: "KeyletCore", dependencies: ["CSQLite"]),
    .executableTarget(
      name: "keylet",
      dependencies: [
        "KeyletCore", .product(name: "ArgumentParser", package: "swift-argument-parser"),
      ]),
    .testTarget(name: "KeyletCoreTests", dependencies: ["KeyletCore"]),
  ])
