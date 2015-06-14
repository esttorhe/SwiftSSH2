WORKSPACE = SwiftSSH2.xcworkspace
SCHEME = SwiftSSH2
#SCHEME_OSX = RecExample-OSX
CONFIGURATION = Debug

# Default for `make`
all: ci

build:
	set -o pipefail && xcodebuild -workspace '$(WORKSPACE)' -scheme '$(SCHEME)' -configuration '$(CONFIGURATION)' -sdk iphonesimulator -destination 'name=iPhone 5' build | xcpretty -c
	#set -o pipefail && xcodebuild -workspace '$(WORKSPACE)' -scheme '$(SCHEME_OSX)' -configuration '$(CONFIGURATION)' -sdk iphonesimulator -destination 'name=iPhone 5' build | xcpretty -c

clean:
	xcodebuild -workspace '$(WORKSPACE)' -scheme '$(SCHEME)' clean
	#xcodebuild -workspace '$(WORKSPACE)' -scheme '$(SCHEME_OSX)' clean

test:
	set -o pipefail && xcodebuild -workspace '$(WORKSPACE)' -scheme '$(SCHEME)' -configuration Debug test -sdk iphonesimulator -destination 'name=iPhone 5' | xcpretty -c --test
	#set -o pipefail && xcodebuild -workspace '$(WORKSPACE)' -scheme '$(SCHEME_OSX)' -configuration Debug test -sdk iphonesimulator -destination 'name=iPhone 5' | xcpretty -c --test

setup:
	bundle install
	bundle exec pod install --project-directory=RecExample/

prepare_ci:	setup 

ci: test
