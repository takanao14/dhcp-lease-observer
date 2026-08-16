package main

import (
	"os"

	"github.com/takanao14/dhcp-lease-observer/internal/app"
)

var version = "dev"

func main() {
	os.Exit(app.Main(os.Args[1:], version))
}
