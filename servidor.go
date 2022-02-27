package main

import (
	"encoding/gob"
	"fmt"
	"net"
	"os"
)

//Iniciamos el servidor e intentamos que se puedan aceptar y manejas clientes concurrentemente.
func servidor(ip string, port string) {

	//Le indicamos el protocolo que va a emplear y el puerto en el que va a escuchar.
	s, err := net.Listen("tcp", ip+":"+port)

	//Si hay un error lo mostramos y se termina.
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		c, err := s.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		go handleClient(c)
	}
}

//Manejamos al cliente
func handleClient(c net.Conn) {
	var msg string

	for {
		//Convierte los bytes de entrada del cliente a un string
		err := gob.NewDecoder(c).Decode(&msg)

		if err != nil {
			fmt.Println(err)
			return
		} else {
			fmt.Println("Mensaje: ", msg)
			fmt.Println("Conexion: ", c.LocalAddr())
		}
	}
}

func main() {

	ip := os.Args[1]
	port := os.Args[2]
	go servidor(ip, port)

	var input string
	fmt.Scanln(&input)
}
