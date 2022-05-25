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
	. "lajr1dominio.com/proy/structs"

	_ "github.com/mattn/go-sqlite3"
)

// Meter tambien en la base de datos el nombre hasheado
func checkErrorServer(e error) {
	if e != nil {
		println(e.Error())
	}
}
func ErrorRespuesta() RespuestaS {

	return RespuestaS{ActAny: -1, ErrNum: 2, Msg: "Ha habido un error "}
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

func validarUsuario(sesion DataS) RespuestaS {
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

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
		resp := RespuestaS{
			ActAny: id,
			Msg:    "Has iniciado sesión correctamente",
		}
		return resp
	}

	return ErrorRespuesta()
}

func registrarUsuario(sesion DataS) RespuestaS {
	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()
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
		return ErrorRespuesta()
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
		resp := RespuestaS{
			ActAny: 1,
			Msg:    "Se ha registrado el usuario correctamente",
		}
		return resp
	}

	return ErrorRespuesta()
}

func getVersion(idUsuario string, nombreArchivo []byte) int {
	sentenciaSelect := `select MAX(version) from file where userId = ? and nameHashed = ?`

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

func añadirArchivoServer(sesion DataS) RespuestaS {

	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}

	version := getVersion(string(sesion.User.Archivo.Token), sesion.User.Archivo.NameH)
	sentencia := `insert into file (userId,name,nameHashed,peso,version,content) values (?,?, ?, ?, ?, ?)`

	statement, err := db.Prepare(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}

	_, err = statement.Exec(string(sesion.User.Archivo.Token), sesion.User.Archivo.NameFile,
		sesion.User.Archivo.NameH, sesion.User.Archivo.Peso, version+1, sesion.User.Archivo.Data)

	if err != nil {
		println(err.Error())
		return ErrorRespuesta()
	}
	info := RespuestaS{
		ActAny: 1,
		Msg:    "Se ha podido subir tu archivo correctamente",
	}
	if version != 0 {
		info.Msg = "Se ha subido la version " + strconv.Itoa(version+1) + " de tu archivo"
	}
	return info
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

			exit := false
			for !exit { // escaneamos la conexión
				dec := json.NewDecoder(conn)
				var msg DataS
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
				case 3:
					resp := añadirArchivoServer(msg)
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
