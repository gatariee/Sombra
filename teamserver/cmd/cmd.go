package cmd

import (
	"net/http"
	"sync"

	"sombra/cmd/crypto"
	"sombra/cmd/listeners"
	"sombra/cmd/storage"
	"sombra/pkg/logger"
)

func SombraInit(ip string, port string, ops *Operators) error {
	sharedState := listeners.NewState()

	logger.Debug("generating server keys")
	serverKeys, err := crypto.GenerateRSAKeys()
	if err != nil {
		return err
	}

	logger.Debug("saving server keys")

	if err := storage.SaveServerKeys("data", serverKeys.PublicKey, serverKeys.PrivateKey); err != nil {
		return err
	}

	server := &Sombra{
		IP:          ip,
		Port:        port,
		Ops:         ops,
		Keys:        serverKeys,
		Servers:     make(map[string]*http.Server),
		sharedState: sharedState,
		sharedData:  &sharedState.Data,
		mu:          sync.Mutex{},
	}

	return server.Start()
}
