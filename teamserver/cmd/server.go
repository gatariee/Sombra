/*

TODO:
 * Implement security on the endpoints to create/kill listeners, based on the Operator struct
 *

*/

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"sombra/cmd/crypto"
	"sombra/cmd/listeners"

	"github.com/gin-gonic/gin"
)

type Sombra struct {
	IP          string
	Port        string
	Ops         *Operators
	Keys        *crypto.ServerKeys
	Servers     map[string]*http.Server
	Shared      listeners.Shared
	sharedData  *listeners.Shared
	sharedState *listeners.State
	mu          sync.Mutex
}

type NewListener struct {
	Port string `json:"port"`
}

type KillListener struct {
	Port string `json:"port"`
}

func (s *Sombra) Start() error {
	fmt.Println("Starting server on", s.IP+":"+s.Port)

	router := gin.Default()
	router.POST("/start", s.handleNewListener)
	router.POST("/stop", s.handleStopListener)
	router.GET("/agents", s.getAgents)

	return http.ListenAndServe(s.IP+":"+s.Port, router)
}

func (s *Sombra) GetCurrentSharedData() listeners.Shared {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.sharedData
}

func (s *Sombra) getAgents(c *gin.Context) {
	data := s.GetCurrentSharedData()
	c.JSON(http.StatusOK, gin.H{"agents": data.AgentList})
}

func (s *Sombra) handleStopListener(c *gin.Context) {
	var req struct {
		Port string `json:"port"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if err := s.stopListener(req.Port); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Listener on port " + req.Port + " has been stopped"})
}

func (s *Sombra) handleNewListener(c *gin.Context) {
	var NewListener NewListener

	if err := c.BindJSON(&NewListener); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if err := s.startNewListener(NewListener.Port); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start new listener"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "New listener started on port " + NewListener.Port})
}

func (s *Sombra) startNewListener(port string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.NewListener(port)
}

func (s *Sombra) NewListener(port string) error {
	if _, exists := s.Servers[port]; exists {
		return fmt.Errorf("server on port %s already exists", port)
	}

	err := listeners.Start(port, s.sharedState, s.Keys.PublicKey, s.Keys.PrivateKey)
	// passes a copy of Sombra, not the actual struct
	if err != nil {
		panic(err)
	}
	s.Servers[port] = &http.Server{Addr: ":" + port, Handler: nil}
	return nil
}

func (s *Sombra) stopListener(port string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, exists := s.Servers[port]
	if !exists {
		return fmt.Errorf("server on port %s not found", port)
	}

	if err := server.Shutdown(context.Background()); err != nil {
		return fmt.Errorf("error shutting down server on port %s: %v", port, err)
	}

	delete(s.Servers, port)
	fmt.Printf("Server on port %s has been stopped\n", port)
	return nil
}
