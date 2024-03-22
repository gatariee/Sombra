package listeners

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

type Agent struct {
	IP       string
	ExtIP    string
	Hostname string
	Sleep    string
	Jitter   string
	OS       string
	UID      string
	PID      string
}

type Task struct {
	UID       string
	CommandID string
	Command   string
}

type Result struct {
	CommandID string
	Result    string
}

type Callback struct {
	AgentUID     string
	LastCallback int
}

type State struct {
	Data Shared
	mu   sync.Mutex
}

type Shared struct {
	AgentList      []Agent
	AgentTasks     []Task
	AgentResults   []Result
	AgentCallbacks []Callback
}

type Route struct {
	Method  string
	Path    string
	Handler gin.HandlerFunc
}

type RouteConfig struct {
	Routes []Route
}

func NewState() *State {
	return &State{
		Data: Shared{},
	}
}

func (s *State) AddAgent(agent Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data.AgentList = append(s.Data.AgentList, agent)
}

func Start(port string, sharedState *State) error {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})

	r.POST("/register", func(c *gin.Context) {
		var agent Agent
		if err := c.BindJSON(&agent); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		fmt.Println("[http.go] Registering agent:", agent)

		sharedState.AddAgent(agent)

		c.JSON(http.StatusOK, gin.H{"message": "Agent registered"})
	})

	go func() {
		if err := r.Run(":" + port); err != nil {
			panic(err) // Consider logging instead of panicking for production code.
		}
	}()

	return nil
}
