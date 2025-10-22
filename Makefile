
wgtunnel: main.go go.mod go.sum
	CGO_ENABLED=0 go build -ldflags="-s -w"
