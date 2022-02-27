package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"net"
	"os"
)

func cliente(ip string, port string) {

	connection, err := net.Dial("tcp", ip+":"+port)

	if err != nil {
		fmt.Println(err)
		return
	}

	var msg string

	for msg != "fin" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		msg = scanner.Text()
		fmt.Printf("You typed: %q\n", msg)

		err = gob.NewEncoder(connection).Encode(&msg)

		if err != nil {
			fmt.Println(err)
		}
	}
	connection.Close()
}

func main() {

	ip := os.Args[1]
	port := os.Args[2]

	cliente(ip, port)
}
