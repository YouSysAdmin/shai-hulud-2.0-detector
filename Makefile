BINARY=shai-hulud-detector
LDFLAGS=-s -w
BUILD_DIR=build

all: linux linux_arm windows mac_amd mac_arm

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-linux-amd64 .

linux_arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-linux-arm64 .

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe .

mac_amd:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
		go build -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-darwin-amd64 .

mac_arm:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
		go build -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-darwin-arm64 .

clean:
	rm -rf $(BUILD_DIR)
