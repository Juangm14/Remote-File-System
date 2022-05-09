package main

import (
	"bufio"
	"crypto/sha512"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	_ "github.com/mattn/go-sqlite3"
)

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func validarUsuario(sesion string) int {
	db, err := sql.Open("sqlite3", "user.db")

	user := strings.Split(sesion, "|")

	sentencia := `Select name, password, id from user where name = ?`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	validacion := statement.QueryRow(user[0])

	var name string
	var password string
	var id string
	validacion.Scan(&name, &password, &id)
	userID, err := strconv.Atoi(id)

	sentenciaSalt := `Select salt from salt where userId = ? `
	statementSalt, err := db.Prepare(sentenciaSalt)

	if err != nil {
		log.Fatalln(err.Error())
	}

	validacionSalt := statementSalt.QueryRow(userID)

	var saltS string

	validacionSalt.Scan(&saltS)

	salt := []byte(saltS)

	passwordSalted := pbkdf2.Key([]byte(user[1]), salt, 4096, 32, sha512.New512_256)

	if name == user[0] && string(passwordSalted) == password {
		return 3
	}

	return 2
}

func registrarUsuario(sesion string) int {
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}

	user := strings.Split(sesion, "|")
	salt := make([]byte, 32)
	password := pbkdf2.Key([]byte(user[1]), salt, 4096, 32, sha512.New512_256)
	sentencia := `insert into user (name,password) values (?, ?)`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	v, err := statement.Exec(user[0], password)
	if err != nil {
		return 0
	} else if v != nil {
		sentenciaUser := `select id from user where name=?`
		statement, err = db.Prepare(sentenciaUser)
		if err != nil {
			log.Fatalln(err.Error())
		}
		v2 := statement.QueryRow(user[0])
		sentenciaSal := `insert into salt (userId,salt) values (?, ?)`
		statement, err = db.Prepare(sentenciaSal)
		if err != nil {
			log.Fatalln(err.Error())
		}
		var userIDs string
		v2.Scan(&userIDs)
		userID, err := strconv.Atoi(userIDs)
		if err != nil {
			fmt.Println("Error con el select")
		}
		v, err = statement.Exec(userID, salt)
		ruta := "./Servidor/" + user[0]
		os.Mkdir(ruta, os.ModePerm)
		return 1
	}

	return -1
}

func añadirArchivo(msg string) int {

	println("ESTO ES EL MENSAJE: " + msg)
	/*db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}

	db.Exec(`insert into file values (?, ? ,? ,?)`)

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	v, err := statement.Exec(3)
	if err != nil {
		return 0
	}*/
	return 1
}

func splitFunc(s string) (string, string) {

	action := ""
	user := ""
	isUser := false
	for _, r := range s {
		if isUser && r != '#' {
			action = action + string(r)
		} else if r != '#' {
			user = user + string(r)
		} else {
			isUser = true
		}
	}

	return action, user
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
			msg := ""
			action := ""
			mensaje := ""
			data := ""

			for scanner.Scan() { // escaneamos la conexión
				msg = scanner.Text()

				if action == "" {
					mensaje, action = splitFunc(msg)
				}

				if action == "1" {
					fmt.Fprintln(conn, validarUsuario(mensaje))
					action = ""
				} else if action == "2" {
					fmt.Fprintln(conn, registrarUsuario(mensaje))
					action = ""
				} else if action == "3" {
					if !strings.Contains(msg, "FIN") {
						data += msg
					} else {
						data += msg
						fmt.Fprintln(conn, añadirArchivo(data))
						action = ""
					}
				}

				// enviamos ack al cliente
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
