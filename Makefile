.PHONY: build test bundle unsigned-bundle smoke sign clean
# Freeze raw values before Make can expand expressions in filenames or other inputs.
override PROFILE := $(value PROFILE)
override IDENTITY := $(value IDENTITY)
override TEAM_ID := $(value TEAM_ID)
override SIGNING_MODE := $(value SIGNING_MODE)
override SIGNING_KEYCHAIN := $(value SIGNING_KEYCHAIN)
# Inputs are then passed through the environment, never interpolated into shell code.
export PROFILE IDENTITY TEAM_ID SIGNING_MODE SIGNING_KEYCHAIN
build:
	swift build -c release
test:
	swift test
	python3 -m unittest discover -s scripts -p 'test_*.py'
# An unsigned, isolated app-like CLI bundle; never installs, signs or launches it.
bundle: build
	mkdir -p dist/Keylet.app/Contents/MacOS dist/Keylet.app/Contents/Resources
	cp LICENSE NOTICE.md dist/Keylet.app/Contents/Resources/
	mkdir -p dist/Keylet.app/Contents/Resources/Licenses
	cp licenses/swift-argument-parser-LICENSE.txt dist/Keylet.app/Contents/Resources/Licenses/
	cp packaging/Info.plist dist/Keylet.app/Contents/Info.plist
	install -m 755 packaging/keylet-ssh-sign dist/Keylet.app/Contents/Resources/keylet-ssh-sign
	cp "$$(swift build -c release --show-bin-path)/keylet" dist/Keylet.app/Contents/MacOS/keylet
unsigned-bundle: build
	python3 scripts/bundle_unsigned.py
smoke: unsigned-bundle
	python3 scripts/cli-smoke.py dist/unsigned/Keylet.app/Contents/MacOS/keylet
sign:
	python3 scripts/sign_bundle.py
clean:
	swift package clean
