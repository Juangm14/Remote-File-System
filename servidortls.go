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

	"golang.org/x/crypto/pbkdf2"

	_ "github.com/mattn/go-sqlite3"
)

type DataS struct {
	Action int   `json:"action"`
	User   UserS `json:"user"`
}
type UserS struct {
	Name     []byte `json:"name"`
	Password []byte `json:"password"`
	Archivo  FileS  `json:"archivo"`
}

type FileS struct {
	NameFile []byte `json:"nameFile"`
	NameH    []byte `json:"nameH"`
	Peso     int    `json:"peso"`
	Data     []byte `json:"data"`
	Token    []byte `json:"token"`
	Id       int
	Version  int
}

type RespuestaS struct {
	ActAny int
	ErrNum int
	Msg    string
	File   FileS
	Data   []byte
	Files  []FileS
}

// Meter tambien en la base de datos el nombre hasheado
func checkErrorServer(e error) {
	if e != nil {
		println(e.Error())
	}
}
func ErrorRespuesta() RespuestaS {

	return RespuestaS{ActAny: -1, ErrNum: 2, Msg: "Ha habido un error "}
}
func consultarArchivosServer(sesion DataS) RespuestaS {
	db, err := sql.Open("sqlite3", "user.db")
	checkErrorServer(err)
	defer db.Close()
	sentencia := `Select id, name, peso, version,content from file where userId = ?`

	statement, err := db.Prepare(sentencia)
	lineas, err := statement.Query(string(sesion.User.Archivo.Token))
	checkErrorServer(err)
	resp := RespuestaS{}
	for lineas.Next() {

		var name []byte
		var id int
		var peso int
		var version int
		var content []byte
		lineas.Scan(&id, &name, &peso, &version, &content)
		file := FileS{
			NameFile: name,
			Id:       id,
			Peso:     peso,
			Version:  version,
			Data:     content,
			Token:    sesion.User.Archivo.Token,
		}
		resp.Files = append(resp.Files, file)
	}

	return resp
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

func eliminarArchivoServer(archivo FileS) RespuestaS {

	db, err := sql.Open("sqlite3", "user.db")
	defer db.Close()

	checkErrorServer(err)
	sentencia := `delete from file where userId = ? and id = ?`

	statement, err := db.Prepare(sentencia)
	checkErrorServer(err)
	num, _ := strconv.Atoi(string(archivo.Token))
	_, err = statement.Exec(num, archivo.Id)

	if err == nil {
		resp := RespuestaS{
			Msg: "Se ha eliminado el archivo correctamente",
		}
		return resp
	}
	checkErrorServer(err)
	return ErrorRespuesta()

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
				case 4, 5:
					resp := consultarArchivosServer(msg)
					enc := json.NewEncoder(conn)
					enc.Encode(resp)
				case 6:
					resp := consultarArchivosServer(msg)
					enc := json.NewEncoder(conn)
					enc.Encode(resp) //Devuelve la consulta
					dec2 := json.NewDecoder(conn)
					var data DataS
					dec2.Decode(&data)
					resp2 := eliminarArchivoServer(data.User.Archivo)

					enc2 := json.NewEncoder(conn)
					enc2.Encode(resp2)
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
