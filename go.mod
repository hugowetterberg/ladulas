module github.com/hugowetterberg/ladulas

go 1.26.5

require (
	connectrpc.com/connect v1.20.0
	filippo.io/age v1.3.1
	github.com/dicebear/dicebear-go/v10 v10.5.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/prometheus/client_golang v1.24.1
	github.com/urfave/cli/v3 v3.10.1
	github.com/wailsapp/wails/v3 v3.0.0-beta.5
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	google.golang.org/protobuf v1.36.11
)

require (
	filippo.io/hpke v0.4.0 // indirect
	git.sr.ht/~jackmordaunt/go-toast/v2 v2.0.3 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/dicebear/schema v1.4.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	golang.org/x/text v0.40.0 // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
