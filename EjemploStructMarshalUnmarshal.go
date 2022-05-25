// You can edit this code!
// Click here and start typing.
package main

import (
	"encoding/json"
	"fmt"
)

type DataServer1 struct {
	Action int         `json:"action"`
	Info   UserServer1 `json:"info"`
}
type UserServer1 struct {
	Name     []byte      `json:"name"`
	Password []byte      `json:"password"`
	Archivo  FileServer1 `json:"archivo"`
}

type FileServer1 struct {
	NameFile []byte `json:"nameFile"`
	NameH    []byte `json:"nameH"`
	Peso     int    `json:"peso"`
	Data     []byte `json:"data"`
	Token    []byte `json:"token"`
}

func main() {
	data := DataServer1{
		Action: 1,
		Info: UserServer1{
			Name:     []byte("PEDRO"),
			Password: []byte("Alberto"),
			Archivo: FileServer1{
				NameFile: nil,
				NameH:    nil,
				Peso:     0,
				Data:     nil,
				Token:    nil,
			},
		},
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	var mensaje DataServer1
	_ = json.Unmarshal(bytes, &mensaje)

	fmt.Println(string(mensaje.Info.Name))
}
