package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"github.com/kayrus/gof5/pkg/client"
)

var Version = "dev"

func main() {
	var server string
	var username string
	var password string
	var sessionID string
	var closeSession bool
	var debug bool
	var sel bool
	var version bool
	var profileIndex int
	flag.StringVar(&server, "server", "", "")
	flag.StringVar(&username, "username", "", "")
	flag.StringVar(&password, "password", "", "")
	flag.StringVar(&sessionID, "session", "", "Reuse a session ID")
	flag.BoolVar(&closeSession, "close-session", false, "Close HTTPS VPN session on exit")
	flag.BoolVar(&debug, "debug", false, "Show debug logs")
	flag.BoolVar(&sel, "select", false, "Select a server from available F5 servers")
	flag.BoolVar(&version, "version", false, "Show version and exit cleanly")
	flag.IntVar(&profileIndex, "profile-index", 0, "If multiple VPN profiles are found chose profile n")

	flag.Parse()

	info := fmt.Sprintf("gof5 %s compiled with %s for %s/%s", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if version {
		fmt.Println(info)
		os.Exit(0)
	}

	log.Print(info)

	if server == "" {
		log.Fatal("Please define --server parameter")
	}

	if u, err := user.Current(); err != nil {
		log.Fatalf("Failed to detect current user ID: %s", err)
	} else if u.Uid != "0" {
		log.Fatalf("Program must be executed under root")
	}

	err := client.Connect(server, username, password, sessionID, closeSession, sel, debug, profileIndex)
	if err != nil {
		log.Fatal(err)
	}
}
