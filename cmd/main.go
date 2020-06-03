package main

import (
	"flag"
	"log"
	"os/user"

	"github.com/kayrus/gof5/pkg"
)

var Version = "dev"

func main() {
	var server string
	var username string
	var password string
	var closeSession bool
	var debug bool
	var sel bool
	flag.StringVar(&server, "server", "", "")
	flag.StringVar(&username, "username", "", "")
	flag.StringVar(&password, "password", "", "")
	flag.BoolVar(&closeSession, "close-session", false, "Close HTTPS VPN session on exit")
	flag.BoolVar(&debug, "debug", false, "Show debug logs")
	flag.BoolVar(&sel, "select", false, "Select a server from available F5 servers")
	flag.Parse()

	log.Printf("gof5 version: %s\n", Version)

	if server == "" {
		log.Fatal("Please define --server parameter")
	}

	if u, err := user.Current(); err != nil {
		log.Fatalf("Failed to detect current user ID: %s", err)
	} else if u.Uid != "0" {
		log.Fatalf("Program must be executed under root")
	}

	pkg.SetDebug(debug)
	err := pkg.Connect(server, username, password, closeSession, sel)
	if err != nil {
		log.Fatal(err)
	}
}
