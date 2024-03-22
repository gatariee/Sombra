package cmd

import (
	"net/http"
	"sync"

	"sombra/cmd/listeners"
)

func SombraInit(ip string, port string, ops *Operators) error {
	sharedState := listeners.NewState()

	server := &Sombra{
		IP:          ip,
		Port:        port,
		Ops:         ops,
		Servers:     make(map[string]*http.Server),
		sharedState: sharedState,
		sharedData:  &sharedState.Data,
		mu:          sync.Mutex{},
	}

	return server.Start()
}
