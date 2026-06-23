package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ricky-Hao/iwand/server"
)

func main() {
	configPath := flag.String("config", "", "path to iwand-server JSON config")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("missing required -config path")
	}

	config, err := server.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	logger := log.New(os.Stderr, "iwand-server: ", log.LstdFlags)
	iwanServer, err := server.New(config, logger)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err = iwanServer.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("serve: %v", err)
	}
}
