# Provenance

This standalone Swift package adapts narrow portions of Secretive, copyright (c) 2020 Max Goedjen, under its MIT license. The upstream license is preserved verbatim in LICENSE. New work in this prototype is also available under MIT.

Reviewed upstream source: https://github.com/maxgoedjen/secretive at `9edc8799009a9d4fb30b45c13689d19e7c31a3c7`.
Reviewed PR #819 source: https://github.com/maxgoedjen/secretive/pull/819 at `86340e2797635ce0d35737e83458211e15cdf43d` (actual fetched commit, not an assumed merged release).

* SSHWire.swift adapts SSHProtocolKit LengthAndData, OpenSSHPublicKeyWriter and OpenSSHSignatureWriter P256 string/mpint encoding. Its bounded reader and restricted agent dispatch are local implementations.
* KeyStore.swift adapts SecureEnclaveStore/SecureEnclaveCreationOptions persistence and PR #819's per-key accessibility choice and independent protection-class inventory recovery. It uses a dedicated identity/service/group and has no migration or key-update API.
* The public SEC1 fixture and expected OpenSSH serialization in CoreTests.swift originate from Secretive's public-key tests. No private fixture is included.

There is no runtime or package dependency on Secretive or its pending PR. This code does not contain its GUI, updater, smartcard support, login items, XPC services, preferences or migrations.

Apple Swift Argument Parser 1.8.2 is linked under Apache License 2.0, pinned to `6a52f3251125d74daf04fcbd5e6f08a75d074382` in Package.resolved. Its unmodified license is in licenses/swift-argument-parser-LICENSE.txt and distributed in Contents/Resources/Licenses. System SQLite is provided by macOS; no separate SQLite package is vendored.
