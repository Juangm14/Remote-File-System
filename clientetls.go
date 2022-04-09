package main

import (
	"bufio"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"os"
	"unicode"
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

func validarConstraseña(s string) bool {
	upper := false
	lower := false
	number := false
	symbol := false

	if len(s) < 10 {
		return false
	}

	for _, r := range s {
		if unicode.IsUpper(r) && unicode.IsLetter(r) {
			upper = true
		} else if unicode.IsLower(r) && unicode.IsLetter(r) {
			lower = true
		} else if unicode.IsNumber(r) {
			number = true
		} else if unicode.IsSymbol(r) {
			symbol = true
		}
	}

	return (upper && lower && number && symbol)
}

func hashPassword(password []byte) []byte {
	hash := sha512.Sum512(password)
	return hash[:]
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
	return "1" + name + "|" + password
}

func registro() string {
	name := ""
	scanner := bufio.NewScanner(os.Stdin)
	for name == "" {
		fmt.Println("Introduce tu nombre de usuario ")
		scanner.Scan()
		name = scanner.Text()
	}

	password := ""
	password2 := ""

	for password == "" || password2 != password {
		if password != password2 {
			fmt.Println("Las contraseñas no son iguales, intentalo de nuevo.")
		}

		validation := false
		for !validation {
			fmt.Println("Introduce tu contraseña: ")
			scanner.Scan()
			password = scanner.Text()
			validation = validarConstraseña(password)
			if !validation {
				fmt.Println("La contraseña no cumple los requisitos (require una minuscula, una mayuscula, un numero, un simbolo y tamaño minimo de 10)")
			}
		}
		for !validarConstraseña(password2) {
			fmt.Println("Confirma tu contraseña: ")
			scanner.Scan()
			password2 = scanner.Text()
		}
	}

	//Ahora hasheamos la contraseña para la seguridad en la comunicacion entre cliente y servidor ( a parte de tener tls )
	password = string(hashPassword([]byte(password)))
	fmt.Println(password)
	return "2" + name + "|" + password
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
			user := registro()
			netscan := bufio.NewScanner(conn)
			fmt.Fprintln(conn, user) // enviamos la entrada al servidor
			netscan.Scan()           // escaneamos la conexión (se bloquea hasta recibir información)
			fmt.Println("servidor: " + netscan.Text())
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
