package main

import (
	"flag"
	"log"
	"os/user"

	"github.com/kayrus/gof5/pkg"
)

func main() {
	var server string
	var username string
	var password string
	var closeSession bool
	var debug bool
	flag.StringVar(&server, "server", "", "")
	flag.StringVar(&username, "username", "", "")
	flag.StringVar(&password, "password", "", "")
	flag.BoolVar(&closeSession, "close-session", false, "Close HTTPS VPN session on exit")
	flag.BoolVar(&debug, "debug", false, "Show debug logs")
	flag.Parse()

	if server == "" {
		log.Fatal("Please define --server parameter")
	}

	if username == "" {
		log.Fatal("Please define --username parameter")
	}

	if password == "" {
		log.Fatal("Please define --password parameter")
	}

	if u, err := user.Current(); err != nil {
		log.Fatalf("Failed to detect current user ID: %s", err)
	} else if u.Uid != "0" {
		log.Fatalf("Program must be executed under root")
	}

	err := pkg.Connect(server, username, password, closeSession, debug)
	if err != nil {
		log.Fatal(err)
	}
}
