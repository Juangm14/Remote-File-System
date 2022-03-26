package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"os"
)

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func menu() string {
	fmt.Println("Bienvenido a tu Sistema de archivos seguro!")
	fmt.Println("1. Iniciar Sesion")
	fmt.Println("2. Registrarse")
	fmt.Println("3. Salir")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	msg := scanner.Text()
	return msg
}

func iniciarSesion() string {
	name := ""
	scanner := bufio.NewScanner(os.Stdin)
	for name == "" {
		fmt.Println("Introduce tu nombre de usuario ")
		scanner.Scan()
		name = scanner.Text()
	}

	password := ""
	for password == "" {
		fmt.Println("Introduce tu contraseña: ")
		scanner.Scan()
		password = scanner.Text()
	}
	return name + "|" + password
}

func registro() {

}

func client(ip string, port string) {
	// desactivamos la comprobación del certificado (útil en desarrollo con certificado autofirmado)
	cfg := &tls.Config{InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", ip+":"+port, cfg) // llamamos al servidor con esa configuración
	checkError(err)

	defer conn.Close() // es importante cerrar la conexión al finalizar

	fmt.Println("conectado a ", conn.RemoteAddr())

	//keyscan := bufio.NewScanner(os.Stdin) // scanner para la entrada estándar (teclado)
	//netscan := bufio.NewScanner(conn)     // scanner para la conexión (datos desde el servidor)
	salida := "0"

	for salida != "3" {

		salida = menu()

		if salida == "1" {
			user := iniciarSesion() // scanner para la entrada estándar (teclado)
			netscan := bufio.NewScanner(conn)
			fmt.Fprintln(conn, user) // enviamos la entrada al servidor
			netscan.Scan()           // escaneamos la conexión (se bloquea hasta recibir información)
			fmt.Println("servidor: " + netscan.Text())
		} else if salida == "2" {
			registro()
		}
	}
}

func main() {
	ip := "127.0.0.1"
	port := "8000"

	if len(os.Args) == 2 {
		ip = os.Args[1]
		port = os.Args[2]
	}

	client(ip, port)
}
