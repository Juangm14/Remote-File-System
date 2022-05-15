package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
)

var token = ""
var key []byte

/*
Observaciones prof.: Algunos comentarios (copio y pego): "Los archivos privados de cada usuario se cifrarán con RSA (clave pública) 3072 bits."
No se cifra con clave pública información en general. En todo caso, se cifra con criptografía convencional y sólo la clave empleada (mucho menor en tamaño y por lo tanto en coste computacional)
 se cifra con clave pública. "No tenemos muy claro donde almacenar las claves privadas (AES) de los usuarios."
 Como comentamos por tutoría, las claves de los usuarios se derivan de su contraseña, pero no se almacenan, se mantienen en RAM mientras dure la sesión
*/

func msgNumber(valor int64, user string) string {
	switch valor {
	case 0:
		return "Ya hay un usuario registrado con este nombre"
	case 1:
		return "Se ha registrado correctamente. " + user + ", bienvenido a tu sistema de archivos "
	case 2:
		return "Las credenciales no so correctas, intentalo de nuevo."
	case 3:
		return "Has iniciado sesion correctamente."
	default:
		return "Ha habido un error inesperado en el servidor. Intentalo de nuevo."
	}
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

func checkError(e error) {
	if e != nil {
		println(e.Error())
	}
}

func menu() string {
	fmt.Println("0. Salir")

	if token == "" {
		fmt.Println("1. Iniciar Sesion")
		fmt.Println("2. Registrarse")
	} else {
		fmt.Println("1. Consultar mis archivos")
		fmt.Println("2. Añadir un archivo al servidor")
		fmt.Println("3. Descargar un archivo del servidor")
		fmt.Println("4. Eliminar un archivo del servidor")
		fmt.Println("5. Cerrar sesión")
	}

	var msg string
	fmt.Scan(&msg)
	return msg
}

//CIFRADO
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//DESCIFRAR
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.RawStdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func validarConstraseña(s string) bool {
	upper := false
	lower := false
	number := false
	if len(s) < 10 {
		return false
	}

	for _, r := range s {
		if unicode.IsUpper(r) && unicode.IsLetter(r) {
			upper = true
		} else if unicode.IsLower(r) && unicode.IsLetter(r) {
			lower = true
		} else if unicode.IsDigit(r) {
			number = true
		}
	}

	return (upper && lower && number)
}

func hashPassword(password []byte) []byte {
	hash := sha512.Sum512(password)
	return hash[:]
}

func iniciarSesion() string {
	var name string
	var password string

	for name == "" {
		fmt.Println("Introduce tu nombre de usuario ")
		fmt.Scan(&name)
	}

	for password == "" {
		fmt.Println("Introduce tu contraseña: ")
		fmt.Scan(&password)
		password = string(hashPassword([]byte(password)))
	}

	key = []byte(password[0:16])
	nameEnc, _ := AesEncrypt([]byte(name), key)

	mensaje := "1#" + string(nameEnc) + "|" + password
	return mensaje
}

func validarNombre(s string) int {
	valido := 1
	for _, r := range s {
		if r == '#' || r == '|' {
			valido = -1
			break
		}
		if len(s) == 1 && r == '0' {
			valido = -2
			break
		}
	}
	return valido
}
func registro() string {
	name := ""
	scanner := bufio.NewScanner(os.Stdin)
	nameValid := -1
	fmt.Println("Introduce tu nombre de usuario ")
	for name == "" || nameValid == -1 {
		scanner.Scan()
		name = scanner.Text()
		nameValid = validarNombre(name)
		if nameValid == -1 || name == "" {
			fmt.Println("El nombre de usuario no es válido, vuelva a introducirlo (escriba 0 solo si quieres salir)")
			name = ""
		}
	}
	if nameValid == -2 {
		return "Has salido correctamente"
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
				fmt.Println("La contraseña no cumple los requisitos (require una minuscula, una mayuscula, un numero y tamaño minimo de 10)")
			}
		}
		for !validarConstraseña(password2) {
			fmt.Println("Confirma tu contraseña: ")
			scanner.Scan()
			password2 = scanner.Text()
		}
	}

	//Ahora hasheamos la contraseña para la seguridad en la comunicacion entre cliente y servidor ( a parte de tener tls )
	hashPassword := hashPassword([]byte(password))
	password = string(hashPassword)

	key = []byte(hashPassword[0:16])
	nameEnc, err := AesEncrypt([]byte(name), key)
	print(err)

	return "2#" + string(nameEnc) + "|" + password
}

func sacarNombreArchv(s string) string {
	pos := -1
	for i, r := range s {
		if r == '\\' {
			pos = i
		}
	}

	return s[pos+1 : len(s)]
}

func añadirArchivo(conn *tls.Conn) []byte {

	var ruta string

	fmt.Println("Escribe la ruta del archivo que quieres subir: ")
	fmt.Scan(&ruta)

	file, err := os.Open(ruta)
	checkError(err)
	defer file.Close()

	fileInformation, err := file.Stat()
	checkError(err)

	nombreCifrado, err := AesEncrypt([]byte(sacarNombreArchv(ruta)), key)

	mensaje := "3#" + string(nombreCifrado) + "| " + strconv.FormatInt(fileInformation.Size(), 10) + "| " + token + "| "

	buff := make([]byte, fileInformation.Size())

	_, err = file.Read(buff)

	nameEnc, err := AesEncrypt(buff, key)

	mensaje += string(nameEnc) + "| FIN"

	return []byte(mensaje)
}

func controladorConsulta(consulta string) []string {

	consultas := strings.Split(consulta, "nuevaConsulta")

	println("Estos son tus archivos:")
	println("-------------------------------------------------------------------------------------")
	println("  #  | Nombre\t\t\tPeso\t\t\tVersion")
	println("-------------------------------------------------------------------------------------")

	var ids []string

	for index, r := range consultas {
		if len(r) > 0 {
			datosArchivo := strings.Split(r, "|")
			ids = append(ids, datosArchivo[0])
			name, err := AesDecrypt([]byte(datosArchivo[1]), key)
			checkError(err)
			println("  " + strconv.Itoa(index) + ".  " + string(name) + "\t\t\t" + datosArchivo[2] + "\t\t\t" + datosArchivo[3])
			println("-------------------------------------------------------------------------------------")
		}
	}

	return ids
}

func llamadaConsultar(conn *tls.Conn) []string {
	netscan := bufio.NewScanner(conn)
	fmt.Fprintln(conn, "4#"+token)
	netscan.Scan()
	return controladorConsulta(netscan.Text())
}

func eliminarArchivo(conn *tls.Conn, ids []string) {

	if len(ids) > 0 {
		var posicion int
		println("Introduce la posicion del archivo a eliminar: ")
		fmt.Scan(&posicion)

		for posicion > len(ids) {
			println("El numero que has introducido es incorrecto. Introduce la posicion del archivo a eliminar: ")
			fmt.Scan(&posicion)
		}

		idArchivo := ids[posicion-1]

		netscan := bufio.NewScanner(conn)

		fmt.Fprintln(conn, "6#"+token+"|"+idArchivo)
		netscan.Scan()
		fmt.Println("servidor: " + netscan.Text())
	} else {
		println("No tienes archivos para eliminar. Introduce alguno para ello.")
	}

}

func almacenarArchivo(sentencia string, ruta string) {
	mensajes := strings.Split(sentencia, "| ")

	nombreArchivo, err := AesDecrypt([]byte(mensajes[0]), key)
	checkError(err)
	content, err := AesDecrypt([]byte(mensajes[1]), key)
	checkError(err)

	file, err := os.Create(ruta + string(nombreArchivo))
	defer file.Close()
	if err != nil {
		println("Error al crear el archivo en la ruta. Por favor introduce una ruta válida.")
	} else {
		reader := bytes.NewReader(content)
		io.Copy(file, reader)
	}
}

func descargarArchivo(conn *tls.Conn, ids []string) {
	if len(ids) > 0 {
		var posicion int
		var ruta string

		println("Introduce la posicion del archivo a descargar: ")
		fmt.Scan(&posicion)

		for posicion > len(ids) {
			println("El numero que has introducido es incorrecto. Introduce la posicion del archivo a eliminar: ")
			fmt.Scan(&posicion)
		}

		println("Introduce la ruta de la carpeta donde quieres que se guarde el archivo (acabada en \\): ")
		fmt.Scan(&ruta)

		idArchivo := ids[posicion-1]

		netscan := bufio.NewScanner(conn)

		fmt.Fprintln(conn, "5#"+token+"|"+idArchivo)
		netscan.Scan()

		almacenarArchivo(netscan.Text(), ruta)

	} else {
		println("No tienes archivos para descargar. Introduce alguno para ello.")
	}
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
	salida := "-1"
	fmt.Println("Bienvenido a tu Sistema de archivos seguro!")
	for salida != "0" {

		salida = menu()

		if salida == "1" && token == "" {
			user := iniciarSesion() // scanner para la entrada estándar (teclado)
			netscan := bufio.NewScanner(conn)
			fmt.Fprintln(conn, user) // enviamos la entrada al servidor
			netscan.Scan()           // escaneamos la conexión (se bloquea hasta recibir información)

			msg := netscan.Text()

			msgPartes := strings.Split(msg, "-")
			numero, _ := strconv.ParseInt(msgPartes[0], 0, 64)

			id := msgPartes[1]

			if err != nil {
				println("Error al convertir el id del usuario a integer.")
			}
			_, user = splitFunc(user)

			if numero == 3 {
				token = id
			}

			fmt.Println("servidor: " + msgNumber(numero, user))

		} else if salida == "2" && token == "" {
			user := registro()
			if user != "Has salido correctamente" {
				netscan := bufio.NewScanner(conn)
				fmt.Fprintln(conn, user) // enviamos la entrada al servidor
				netscan.Scan()           // escaneamos la conexión (se bloquea hasta recibir información)
				fmt.Println("servidor: " + netscan.Text())
			} else {
				fmt.Println(user)
			}
		} else if token != "" {
			if salida == "1" {
				ids := llamadaConsultar(conn)
				ids = ids
			} else if salida == "2" {
				netscan := bufio.NewScanner(conn)
				fileContent := añadirArchivo(conn)
				fmt.Fprintln(conn, string(fileContent))
				netscan.Scan()
				fmt.Println("servidor: " + netscan.Text())
			} else if salida == "3" {
				ids := llamadaConsultar(conn)
				descargarArchivo(conn, ids)
			} else if salida == "4" {
				ids := llamadaConsultar(conn)
				eliminarArchivo(conn, ids)
			} else if salida == "5" {
				fmt.Println("Has cerrado sesion correctamente. Esperamos que vuelvas pronto. :( ")
				token = ""
			}
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
