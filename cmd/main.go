package main

import (
	"flag"
	"log"

	"github.com/kayrus/gof5/pkg"
)

func main() {
	var server string
	var username string
	var password string
	var debug bool
	flag.StringVar(&server, "server", "", "")
	flag.StringVar(&username, "username", "", "")
	flag.StringVar(&password, "password", "", "")
	flag.BoolVar(&debug, "debug", false, "Show all the magic")
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

	err := pkg.Connect(server, username, password, debug)
	if err != nil {
		log.Fatal(err)
	}
}
