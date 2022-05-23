// You can edit this code!
// Click here and start typing.
package main

import (
	"encoding/json"
	"fmt"
)

type DataServer struct {
	Action int        `json:"action"`
	Info   UserServer `json:"info"`
}
type UserServer struct {
	Name     []byte     `json:"name"`
	Password []byte     `json:"password"`
	Archivo  FileServer `json:"archivo"`
}

type FileServer struct {
	NameFile []byte `json:"nameFile"`
	NameH    []byte `json:"nameH"`
	Peso     int    `json:"peso"`
	Data     []byte `json:"data"`
	Token    []byte `json:"token"`
}

func main() {
	data := DataServer{
		Action: 1,
		Info: UserServer{
			Name:     []byte("PEDRO"),
			Password: []byte("Alberto"),
			Archivo: FileServer{
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

	var mensaje DataServer
	_ = json.Unmarshal(bytes, &mensaje)

	fmt.Println(string(mensaje.Info.Name))
}
