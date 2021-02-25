package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/kayrus/gof5/pkg/client"
)

var Version = "dev"

func fatal(err error) {
	if runtime.GOOS == "windows" {
		// Escalated privileges in windows opens a new terminal, and if there is an
		// error, it is impossible to see it. Thus we wait for user to press a button.
		log.Printf("%s, press enter to exit", err)
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		os.Exit(1)
	}
	log.Fatal(err)
}

func main() {
	var server string
	var username string
	var password string
	var sessionID string
	var closeSession bool
	var debug bool
	var sel bool
	var version bool
	flag.StringVar(&server, "server", "", "")
	flag.StringVar(&username, "username", "", "")
	flag.StringVar(&password, "password", "", "")
	flag.StringVar(&sessionID, "session", "", "Reuse a session ID")
	flag.BoolVar(&closeSession, "close-session", false, "Close HTTPS VPN session on exit")
	flag.BoolVar(&debug, "debug", false, "Show debug logs")
	flag.BoolVar(&sel, "select", false, "Select a server from available F5 servers")
	flag.BoolVar(&version, "version", false, "Show version and exit cleanly")
	flag.Parse()

	info := fmt.Sprintf("gof5 %s compiled with %s for %s/%s", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if version {
		fmt.Println(info)
		os.Exit(0)
	}

	log.Print(info)

	if err := checkPermissions(); err != nil {
		fatal(err)
	}

	err := client.Connect(server, username, password, sessionID, closeSession, sel, debug)
	if err != nil {
		fatal(err)
	}
}
