package main

import (
	"crypto/sha512"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	_ "github.com/mattn/go-sqlite3"
)

type DataServer struct {
	Action int        `json:"action"`
	User   UserServer `json:"user"`
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

type RespuestaServer struct {
	actionOrAny int
	errorNum    int
	Msg         string
	file        FileServer
	data        []byte
}

// Meter tambien en la base de datos el nombre hasheado
func checkErrorServer(e error) {
	if e != nil {
		println(e.Error())
	}
}

func consultarArchivosServer(sesion string) string {
	db, err := sql.Open("sqlite3", "user.db")
	checkErrorServer(err)
	defer db.Close()
	sentencia := `Select id, name, peso, version from file where userId = ?`

	statement, err := db.Prepare(sentencia)
	datos := ""
	lineas, err := statement.Query(sesion)
	checkErrorServer(err)

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

func validarUsuario(sesion DataServer) RespuestaServer {
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	respError := RespuestaServer{actionOrAny: -1, errorNum: 2, Msg: "Ha habido un error registrandose"}
	sentencia := `Select name, password, id from user where name = ?`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	validacion := statement.QueryRow(sesion.User.Name)

	var name string
	var password string
	var id int
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

	passwordSalted := pbkdf2.Key([]byte(sesion.User.Password), salt, 4096, 32, sha512.New512_256)

	if name == string(sesion.User.Name) && string(passwordSalted) == password {
		resp := RespuestaServer{
			actionOrAny: id,
			Msg:         "Has iniciado sesión correctamente",
		}
		return resp
	}

	return respError
}

func registrarUsuario(sesion DataServer) RespuestaServer {
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()
	respError := RespuestaServer{actionOrAny: -1, errorNum: 2, Msg: "Ha habido un error registrandose"}
	if err != nil {
		log.Fatalln(err.Error())
	}

	salt := make([]byte, 32)
	password := pbkdf2.Key(sesion.User.Password, salt, 4096, 32, sha512.New512_256)
	sentencia := `insert into user (name,password) values (?, ?)`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	v, err := statement.Exec(sesion.User.Name, password)
	if err != nil {
		return respError
	} else if v != nil {
		sentenciaUser := `select id from user where name=?`
		statement, err = db.Prepare(sentenciaUser)
		if err != nil {
			log.Fatalln(err.Error())
		}
		v2 := statement.QueryRow(sesion.User.Name)
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
		ruta := "./Servidor/" + string(sesion.User.Name)
		os.Mkdir(ruta, os.ModePerm)
		resp := RespuestaServer{
			actionOrAny: 1,
			errorNum:    0,
			Msg:         "Se ha registrado el usuario correctamente",
		}
		return resp
	}

	return respError
}

func getVersion(idUsuario string, nombreArchivo string) int {
	sentenciaSelect := `select MAX(version) from file where userId = ? and name = ?`

	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()
	checkErrorServer(err)

	statement, err := db.Prepare(sentenciaSelect)

	validacion := statement.QueryRow(idUsuario, nombreArchivo)

	var version int

	if statement == nil {
		return 0
	}

	validacion.Scan(&version)

	return version
}

func añadirArchivoServer(msg string) int {

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

func eliminarArchivoServer(mensaje string) string {

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

func splitFuncServer(s string) (string, string) {

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

func descargarArchivoServer(mensaje string) string {

	partesMensaje := strings.Split(mensaje, "|")

	sesion := partesMensaje[0]
	id := partesMensaje[1]

	db, err := sql.Open("sqlite3", "user.db")
	checkErrorServer(err)
	defer db.Close()
	sentencia := `Select name, content  from file where userId = ? and id = ?`

	statement, err := db.Prepare(sentencia)
	datos := ""
	lineas, err := statement.Query(sesion, id)
	checkErrorServer(err)

	defer lineas.Close()
	for lineas.Next() {

		var name string
		var content string

		lineas.Scan(&name, &content)

		datos += name + "| " + content

		break
	}

	return datos
}

func servidor(ip string, port string) {
	// cargamos el par certificado / clave privada
	cert, err := tls.LoadX509KeyPair("./tls/localhost.crt", "./tls/localhost.key")
	checkErrorServer(err)

	// asignamos dicho par a la configuración de TLS
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	// creamos un listener para escuchar el puerto 1337
	ln, err := tls.Listen("tcp", ip+":"+port, cfg)
	checkErrorServer(err)

	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	for { // búcle infinito, se sale con ctrl+c o matando el proceso
		conn, err := ln.Accept() // para cada nueva petición de conexión
		checkErrorServer(err)

		go func() { // lanzamos un cierre (lambda, función anónima) en concurrencia

			_, port, err := net.SplitHostPort(conn.RemoteAddr().String()) // obtenemos el puerto remoto para identificar al cliente (decorativo)
			checkErrorServer(err)

			fmt.Println("conexión: ", conn.LocalAddr(), " <--> ", conn.RemoteAddr())

			//action := ""
			//mensaje := ""
			//data := ""
			exit := false
			for !exit { // escaneamos la conexión
				dec := json.NewDecoder(conn)
				var msg DataServer
				dec.Decode(&msg)
				switch msg.Action {
				case 1:
					resp := validarUsuario(msg)
					enc := json.NewEncoder(conn)
					enc.Encode(resp)
				case 2:
					resp := registrarUsuario(msg)
					enc := json.NewEncoder(conn)
					enc.Encode(resp)
				default:
					exit = true
				}

				/*
					if action == "" {
						mensaje, action = splitFuncServer(msg)
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
							fmt.Fprintln(conn, añadirArchivoServer(data))
							action = ""
							data = ""
						}
					} else if action == "4" { //Consultar archivos
						action = ""
						fmt.Fprintln(conn, consultarArchivosServer(mensaje))
					} else if action == "5" {
						action = ""
						fmt.Fprintln(conn, descargarArchivoServer(mensaje))

					} else if action == "6" {
						action = ""
						fmt.Fprintln(conn, eliminarArchivoServer(mensaje))

					}
				*/
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
