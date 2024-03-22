package main

import (
	"fmt"
	"os"

	"sombra/cmd"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ./teamserver <address> <port> <path_to_operators.json>")
		os.Exit(1)
	}

	address := os.Args[1]
	port := os.Args[2]
	operators := os.Args[3]

	ops, err := cmd.LoadOperators(operators)
	if err != nil {
		fmt.Println("Failed to load operators:", err)
		os.Exit(1)
	}

	if err := cmd.SombraInit(address, port, ops); err != nil {
		fmt.Println("Failed to start server:", err)
		os.Exit(1)
	}
}
