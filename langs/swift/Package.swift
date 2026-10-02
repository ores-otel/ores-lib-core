// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OresLibCore",
    products: [.library(name: "OresLibCore", targets: ["OresLibCore"])],
    targets: [
        .target(name: "OresLibCore"),
        .testTarget(name: "OresLibCoreTests", dependencies: ["OresLibCore"]),
    ]
)
