package main

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func validarUsuario(sesion string) string {
	db, err := sql.Open("sqlite3", "user.db")

	defer db.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}

	user := strings.Split(sesion, "|")

	sentencia := `Select name, password from user where name = ? and password = ?`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	validacion := statement.QueryRow(user[0], user[1])
	var name string
	var password string

	validacion.Scan(&name, &password)

	if name == user[0] {
		return "Has iniciado sesion correctamente."
	}

	return "Las credenciales no so correctas, intentalo de nuevo."
}

func servidor(ip string, port string) {
	// cargamos el par certificado / clave privada
	cert, err := tls.LoadX509KeyPair("./tls/localhost.crt", "./tls/localhost.key")
	checkError(err)

	// asignamos dicho par a la configuración de TLS
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	// creamos un listener para escuchar el puerto 1337
	ln, err := tls.Listen("tcp", ip+":"+port, cfg)
	checkError(err)

	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	for { // búcle infinito, se sale con ctrl+c o matando el proceso
		conn, err := ln.Accept() // para cada nueva petición de conexión
		checkError(err)

		go func() { // lanzamos un cierre (lambda, función anónima) en concurrencia

			_, port, err := net.SplitHostPort(conn.RemoteAddr().String()) // obtenemos el puerto remoto para identificar al cliente (decorativo)
			checkError(err)

			fmt.Println("conexión: ", conn.LocalAddr(), " <--> ", conn.RemoteAddr())

			scanner := bufio.NewScanner(conn) // el scanner nos permite trabajar con la entrada línea a línea (por defecto)

			for scanner.Scan() { // escaneamos la conexión
				fmt.Println("cliente[", port, "]: ", scanner.Text()) // mostramos el mensaje del cliente

				fmt.Fprintln(conn, "ack: ", validarUsuario(scanner.Text())) // enviamos ack al cliente
			}

			conn.Close() // cerramos al finalizar el cliente (EOF se envía con ctrl+d o ctrl+z según el sistema)
			fmt.Println("cierre[", port, "]")
		}()
	}
}

func main() {

	ip := "127.0.0.1"
	port := "8000"

	if len(os.Args) == 2 {
		ip = os.Args[1]
		port = os.Args[2]
	}

	servidor(ip, port)
}
