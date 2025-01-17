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
	"sombra/cmd/transport"

	"sombra/pkg/logger"

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

type Listener struct {
	Type string `json:"type"`
	Port string `json:"port"`
}

type KillListener struct {
	Port string `json:"port"`
}

// Operator API
func (s *Sombra) Start() error {
	logger.Info(fmt.Sprintf("starting teamserver on %s:%s", s.IP, s.Port))

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.POST("/start_listener", s.handleNewListener)
	router.POST("/stop_listener", s.handleStopListener)
	router.POST("/task", s.taskHandler)
	router.GET("/agents", s.getAgents)

	return http.ListenAndServe(s.IP+":"+s.Port, router)
}

func (s *Sombra) taskHandler(c *gin.Context) {
	var envelope transport.Envelope
	if err := c.BindJSON(&envelope); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	agent := envelope.Agent
	task := envelope.Task

	if !s.sharedState.VerifyAgent(agent.UID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent"})
		return

	}

	if err := s.UpdateTasks(agent, task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "task received"})
}

func (s *Sombra) GetCurrentSharedData() listeners.Shared {
	/*
		A safe way to get the current shared data without causing an I/O race condition.
	*/
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.sharedData
}

func (s *Sombra) getAgents(c *gin.Context) {
	data := s.GetCurrentSharedData()
	c.JSON(http.StatusOK, gin.H{"agents": data.AgentList})
}

func (s *Sombra) UpdateTasks(agent_data transport.Agent, task_data transport.Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	/* the mutex is locked, so we can safely update the shared data */
	gateway := listeners.Gateway{
		Agent: agent_data,
		Task:  task_data,
	}

	s.sharedData.Gateways = append(s.sharedData.Gateways, gateway)

	//
	// after populating the gateway, we also need to populate the global state
	//

	// append to the agent's task list
	//s.sharedState.Data.AgentTasks[agent_data.UID] = append(s.sharedState.AgentTasks[agent_data.UID], task_data)

	// append to the global task list
	s.sharedState.Data.AgentTasks = append(s.sharedState.Data.AgentTasks, task_data)

	return nil
}

func (s *Sombra) GetAgentKey(uid string) ([]byte, []byte) {
	data := s.GetCurrentSharedData()
	for _, agent := range data.AgentKeys {
		if agent.UID == uid {
			return agent.Nonce, agent.Key
		}
	}
	return nil, nil
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
	var (
		NewListener Listener
	)

	logger.Debug("unwrapped new listener request")

	if err := c.BindJSON(&NewListener); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	logger.Debug(fmt.Sprintf("got request for: %s", NewListener.Type))
	switch NewListener.Type {
	case "http":
		if NewListener.Port == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request, port?"})
			return
		}
		logger.Info(fmt.Sprintf("fulfilling request for: %s listener", NewListener.Type))
		if err := s.startNewListener(NewListener.Port); err != nil {
			logger.Err(fmt.Sprintf("failed to start new listener: %v", err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "New listener started on port " + NewListener.Port})

	default:

		logger.Err(fmt.Sprintf("invalid listener type: %s", NewListener.Type))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid listener type"})
	}
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
	if err != nil {
		return fmt.Errorf("failed to start listener on port %s: %v", port, err)
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
