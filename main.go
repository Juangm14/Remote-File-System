package main

import (
	"fmt"
	"os"

	. "lajr1dominio.com/proy/client"
	. "lajr1dominio.com/proy/server"
)

func main() {
	ip := "127.0.0.1"
	port := "8000"
	open := os.Args[1]
	if len(os.Args) == 4 {
		ip = os.Args[2]
		port = os.Args[3]
	}

	if open == "Server" {
		Server(ip, port)
	} else if open == "Client" {
		Client(ip, port)
	} else {
		fmt.Println("No es una opción viable")
	}

}
