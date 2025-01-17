package main

import (
	"fmt"
	"os"

	"sombra/cmd"
	"sombra/pkg/logger"
)

var Version string = "0.0.1-dev"

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ./teamserver <address> <port> <path_to_operators.json>")
		os.Exit(1)
	}

	var (
		address   = os.Args[1]
		port      = os.Args[2]
		operators = os.Args[3]
	)

	logger.Debug(fmt.Sprintf("loading operators from: %s", operators))
	ops, err := cmd.LoadOperators(operators)
	if err != nil {
		logger.Err(fmt.Sprintf("failed to load operators: %s", err))
		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("successfully loaded %d operators", len(ops.Operators)))

	if err := cmd.SombraInit(address, port, ops); err != nil {
		logger.Err(fmt.Sprintf("failed to initialize Sombra: %s", err))
		os.Exit(1)
	}
}
