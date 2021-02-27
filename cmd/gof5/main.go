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

var (
	Version = "dev"
	info    = fmt.Sprintf("gof5 %s compiled with %s for %s/%s", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
)

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
	var version bool
	var opts client.Options

	flag.StringVar(&opts.Server, "server", "", "")
	flag.StringVar(&opts.Username, "username", "", "")
	flag.StringVar(&opts.Password, "password", "", "")
	flag.StringVar(&opts.SessionID, "session", "", "Reuse a session ID")
	flag.StringVar(&opts.CACert, "ca-cert", "", "Path to a custom CA certificate")
	flag.StringVar(&opts.Cert, "cert", "", "Path to a user TLS certificate")
	flag.StringVar(&opts.Key, "key", "", "Path to a user TLS key")
	flag.BoolVar(&opts.CloseSession, "close-session", false, "Close HTTPS VPN session on exit")
	flag.BoolVar(&opts.Debug, "debug", false, "Show debug logs")
	flag.BoolVar(&opts.Sel, "select", false, "Select a server from available F5 servers")
	flag.IntVar(&opts.ProfileIndex, "profile-index", 0, "If multiple VPN profiles are found chose profile n")
	flag.BoolVar(&version, "version", false, "Show version and exit cleanly")

	flag.Parse()

	if version {
		fmt.Println(info)
		os.Exit(0)
	}

	if opts.ProfileIndex < 0 {
		fatal(fmt.Errorf("profile-index cannot be negative"))
	}

	log.Print(info)

	if err := checkPermissions(); err != nil {
		fatal(err)
	}

	if err := client.Connect(&opts); err != nil {
		fatal(err)
	}
}
