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
		println(e.Error())
	}
}

func consultarArchivos(sesion string) string {
	db, err := sql.Open("sqlite3", "user.db")
	checkError(err)
	defer db.Close()
	sentencia := `Select id, name, peso, version from file where userId = ?`

	statement, err := db.Prepare(sentencia)
	datos := ""
	lineas, err := statement.Query(sesion)
	checkError(err)

	for lineas.Next() {

		var name string
		var id string
		var peso string
		var version string
		lineas.Scan(&id, &name, &peso, &version)

		datos += "nuevaConsulta" + id + "|" + name + "|" + peso + "|" + version

	}

	return datos
}
func validarUsuario(sesion string) string {
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()
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

	sentenciaSalt := `Select salt from salt where userId = ? `
	statementSalt, err := db.Prepare(sentenciaSalt)

	if err != nil {
		log.Fatalln(err.Error())
	}

	validacionSalt := statementSalt.QueryRow(id)

	var saltS string

	validacionSalt.Scan(&saltS)

	salt := []byte(saltS)

	passwordSalted := pbkdf2.Key([]byte(user[1]), salt, 4096, 32, sha512.New512_256)

	if name == user[0] && string(passwordSalted) == password {

		return "3" + "-" + id
	}

	return "2" + "-" + id
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

	v, err := statement.Exec(string(user[0]), password)
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

func getVersion(idUsuario string, nombreArchivo string) int {
	sentenciaSelect := `select MAX(version) from file where userId = ? and name = ?`

	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()
	checkError(err)

	statement, err := db.Prepare(sentenciaSelect)

	validacion := statement.QueryRow(idUsuario, nombreArchivo)

	var version int

	if statement == nil {
		return 0
	}

	validacion.Scan(&version)

	return version
}

func añadirArchivo(msg string) int {

	partesMensaje := strings.Split(msg, "| ")

	nombreArchivo := partesMensaje[0][2:len(partesMensaje[0])]
	pesoArchivo := partesMensaje[1]
	idUsuario := partesMensaje[2]
	contenido := partesMensaje[3]

	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}

	version := getVersion(idUsuario, nombreArchivo)
	sentencia := `insert into file (userId,name,peso,version,content) values (?, ?, ?, ?, ?)`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	_, err = statement.Exec(idUsuario, nombreArchivo, pesoArchivo, version+1, contenido)

	if err != nil {
		println(err.Error())
		return 0
	}
	return 1
}

func eliminarArchivo(mensaje string) string {

	ids := strings.Split(mensaje, "|")
	userID := ids[0]
	fileID := ids[1]
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}
	sentencia := `delete from file where userId = ? and id = ?`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	_, err = statement.Exec(userID, fileID)

	if err == nil {
		return "Eliminado"
	}

	return "Error"

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

				if action == "1" { //Inicio Sesion

					fmt.Fprintln(conn, validarUsuario(mensaje))
					action = ""
				} else if action == "2" { //Registrarse
					fmt.Fprintln(conn, registrarUsuario(mensaje))
					action = ""
				} else if action == "3" { //Añadir Archivo
					if !strings.Contains(msg, "FIN") {
						data = data + msg
					} else {
						data = data + msg
						fmt.Fprintln(conn, añadirArchivo(data))
						action = ""
						data = ""
					}
				} else if action == "4" { //Consultar archivos
					action = ""
					fmt.Fprintln(conn, consultarArchivos(mensaje))
				} else if action == "6" {
					action = ""
					fmt.Fprintln(conn, eliminarArchivo(mensaje))

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
