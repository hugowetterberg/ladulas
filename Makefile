BUF ?= buf
GOBIN ?= $(shell go env GOPATH)/bin
BUILD_DIR ?= $(shell mktemp -d)

.PHONY: all
all: generate lint test

# tools installs the CLIs that are not go tool directives in go.mod. The protoc
# plugins are `go tool` entries and need no installation.
.PHONY: tools
tools:
	go install github.com/bufbuild/buf/cmd/buf@v1.72.0

.PHONY: generate
generate:
	$(BUF) lint
	$(BUF) generate
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./...

# viewer has nothing to compile: the shared bundle in viewer/assets is plain
# HTML, CSS and ES modules with no dependencies and no build step, embedded as
# written. The target runs the checks that keep it that way — no remote
# resources, no markup assignment, no inline code, every import resolving.
.PHONY: viewer
viewer:
	go test ./viewer/

# docs checks that the four documents still reach each other: every relative
# link resolves, and every #anchor is a heading that exists. A renamed heading
# is the failure this catches, because nothing else would — the page still
# renders, and the reader who followed the link lands at the top of a long
# document and gives up.
.PHONY: docs
docs:
	go test ./docs/

# GUI_TAGS selects the desktop build. Wails v3 defaults to GTK 4 and
# webkitgtk-6.0; on a system with GTK 3 and webkit2gtk-4.1 add Wails' gtk3 tag:
#
#	make GUI_TAGS=gui,gtk3 gui
GUI_TAGS ?= gui

# build compiles everything to a scratch directory; no binaries in the tree.
.PHONY: build
build:
	go build -o $(BUILD_DIR)/ ./cmd/...
	@echo "built into $(BUILD_DIR)"

# gui builds the desktop application with the tray and the approval windows.
.PHONY: gui
gui:
	go build -tags $(GUI_TAGS) -o $(BUILD_DIR)/ ./cmd/ladulas
	@echo "built into $(BUILD_DIR)"

# install puts both binaries on the PATH, the desktop one with its GUI.
.PHONY: install
install:
	go install -tags $(GUI_TAGS) ./cmd/ladulas
	go install ./cmd/ladulasd
	go install ./cmd/ladulas-sign

.PHONY: test-gui
test-gui:
	go test -tags $(GUI_TAGS) ./internal/gui/

# ICON_MASTER is the one picture that is drawn by hand. Everything else — the
# tray icon, the theme sizes below — is generated from it or copied from it.
ICON_MASTER ?= internal/branding/icon-1024.png

# icons regenerates the copy internal/branding embeds for the tray. Run it after
# changing the app icon; internal/branding's test fails until you do, which is
# how a copy is allowed to exist at all.
.PHONY: icons
icons:
	magick $(ICON_MASTER) -resize 128x128 -strip internal/branding/tray-128.png
	go test ./internal/branding/

# install-desktop puts the menu entry and the icon theme sizes in the user's own
# directories, for a machine running `make install` rather than a package. It
# needs no root, and it does not touch the login session — that is
# install-autostart below, deliberately separate.
#
# The icon has to be installed for the *window* to have one at all: GTK 4 has no
# API that takes an icon as bytes, so the desktop entry's Icon= is the whole
# mechanism (see internal/gui/gui.go). Exec is rewritten to the installed binary,
# since contrib/ladulas.desktop names /usr/bin for the packages.
XDG_DATA ?= $(HOME)/.local/share
AUTOSTART ?= $(HOME)/.config/autostart
ICON_SIZES = 16 22 24 32 48 64 128 256 512

.PHONY: install-desktop
install-desktop:
	@for size in $(ICON_SIZES); do \
		mkdir -p $(XDG_DATA)/icons/hicolor/$${size}x$${size}/apps; \
		magick $(ICON_MASTER) -resize $${size}x$${size} -strip \
			$(XDG_DATA)/icons/hicolor/$${size}x$${size}/apps/ladulas.png; \
	done
	mkdir -p $(XDG_DATA)/applications
	sed 's|^Exec=.*|Exec=$(GOBIN)/ladulas gui|' contrib/ladulas.desktop \
		> $(XDG_DATA)/applications/ladulas.desktop
	-gtk-update-icon-cache -q -t -f $(XDG_DATA)/icons/hicolor 2>/dev/null || true
	-update-desktop-database -q $(XDG_DATA)/applications 2>/dev/null || true
	@echo "installed the menu entry and the icon"

# install-autostart starts the desktop application at login, which is what the
# packages do by putting the same entry in /etc/xdg/autostart. It is its own
# target because starting something at somebody's login is a decision and not a
# build step, and `make uninstall-autostart` takes it back out.
.PHONY: install-autostart
install-autostart: install-desktop
	mkdir -p $(AUTOSTART)
	cp $(XDG_DATA)/applications/ladulas.desktop $(AUTOSTART)/ladulas.desktop
	@echo "the desktop application will start at login"

.PHONY: uninstall-autostart
uninstall-autostart:
	rm -f $(AUTOSTART)/ladulas.desktop
	@echo "the desktop application will not start at login"

# There is no phone target here: nothing in this repository compiles against
# gomobile, so nothing here notices when a change to pkg/ stops being bindable
# (§21). gomobile takes strings, signed integers, booleans, []byte, errors and
# types declared in the bound package, and an exported signature widened past
# that list builds fine here and then fails where it is bound.
