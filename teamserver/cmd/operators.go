package cmd

import (
	"encoding/json"
	"os"
)

type Operator struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Type     string `json:"Type"`
}

type Operators struct {
	Operators []Operator `json:"Operators"`
}

func LoadOperators(path string) (*Operators, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	operators := &Operators{}
	if err := json.NewDecoder(file).Decode(operators); err != nil {
		return nil, err
	}

	return operators, nil
}

func (o *Operators) GetOperator(username string) *Operator {
	for _, op := range o.Operators {
		if op.Username == username {
			return &op
		}
	}
	return nil
}

func (o *Operators) AddOperator(op Operator) {
	o.Operators = append(o.Operators, op)
}

func (o *Operators) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(o); err != nil {
		return err
	}

	return nil
}
