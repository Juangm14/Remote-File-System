package client

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"unicode"

	. "lajr1dominio.com/proy/structs"
)

var token = ""
var key []byte

//Json para hacer el encode del struct

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

func checkErrorCliente(e error) {
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

func AesEncrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	checkErrorCliente(err)              // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return

}

//DESCIFRAR
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesDecrypt(data, key []byte) (out []byte) {

	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	checkErrorCliente(err)               // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
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

func hashear(password []byte) []byte {
	hash := sha512.Sum512(password)
	return hash[:]
}

func iniciarSesion() DataS {
	var name string
	var password string

	for name == "" {
		fmt.Println("Introduce tu nombre de usuario ")
		fmt.Scan(&name)
	}

	for password == "" {
		fmt.Println("Introduce tu contraseña: ")
		fmt.Scan(&password)
		password = string(hashear([]byte(password)))
	}

	key = []byte(password[0:16])
	nameEnc := hashear([]byte(name))
	info := DataS{
		Action: 1,
		User: UserS{
			Name:     nameEnc,
			Password: []byte(password),
		},
	}

	return info
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
func registro() DataS {
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
		info := DataS{
			Action: -1,
		}
		return info
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
	hashedPassword := hashear([]byte(password))
	password = string(hashedPassword)

	key = []byte(hashedPassword[0:16])
	nameEnc := hashear([]byte(name))

	info := DataS{
		Action: 2,
		User: UserS{
			Name:     nameEnc,
			Password: hashedPassword,
		},
	}

	return info
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

func añadirArchivo(conn *tls.Conn) DataS {

	var ruta string

	fmt.Println("Escribe la ruta del archivo que quieres subir: ")
	fmt.Scan(&ruta)

	file, err := os.Open(ruta)
	checkErrorCliente(err)
	defer file.Close()

	fileInformation, err := file.Stat()
	checkErrorCliente(err)

	nombreCifrado := AesEncrypt([]byte(sacarNombreArchv(ruta)), key)
	nombreHasheado := hashear([]byte(sacarNombreArchv(ruta)))
	mensaje := "3#" + string(nombreCifrado) + "| " + strconv.FormatInt(fileInformation.Size(), 10) + "| " + token + "| "

	buff := make([]byte, fileInformation.Size())

	_, err = file.Read(buff)

	content := AesEncrypt(buff, key)

	mensaje += string(content) + "| FIN"
	info := DataS{
		Action: 3,
		User: UserS{
			Archivo: FileS{NameFile: nombreCifrado,
				NameH: nombreHasheado,
				Peso:  int(fileInformation.Size()),
				Data:  content,
				Token: []byte(token)},
		},
	}
	return info
}

func controladorConsulta(consulta RespuestaS) {

	println("Estos son tus archivos:")
	println("-------------------------------------------------------------------------------------")
	println("  #  | Nombre\t\t\tPeso\t\t\tVersion")
	println("-------------------------------------------------------------------------------------")

	var ids []string

	for index, r := range consulta.Files {

		ids = append(ids, strconv.Itoa(r.Id))
		name := AesDecrypt([]byte(r.NameFile), key)
		println("  " + strconv.Itoa(index) + ".  " + string(name) + "\t\t\t" + strconv.Itoa(r.Peso) + "\t\t\t" + strconv.Itoa(r.Version))
		println("-------------------------------------------------------------------------------------")

	}

}

func llamadaConsultar(conn *tls.Conn, action int) []FileS {
	enc := json.NewEncoder(conn)
	data := DataS{Action: action, User: UserS{
		Archivo: FileS{
			Token: []byte(token),
		},
	}}
	enc.Encode(data)
	dec := json.NewDecoder(conn)
	var resp RespuestaS
	dec.Decode(&resp)
	controladorConsulta(resp)
	return resp.Files
}

func eliminarArchivo(files []FileS) DataS {

	var posicion int

	println("Introduce la posicion del archivo a eliminar: ")
	fmt.Scan(&posicion)
	file := FileS{}
	for index, r := range files {
		if index == posicion {
			file = r
		}
	}
	if file.Peso == 0 {
		println("No tienes archivos para eliminar. Introduce alguno para ello.")
		file.Peso = -1
		return DataS{User: UserS{Archivo: file}}
	} else {

		return DataS{Action: 6, User: UserS{Archivo: file}}
	}

}

func almacenarArchivo(archivo FileS, ruta string) {

	nombreArchivo := AesDecrypt([]byte(archivo.NameFile), key)

	content := AesDecrypt([]byte(archivo.Data), key)
	file, err := os.Create(ruta + string(nombreArchivo))
	defer file.Close()
	if err != nil {
		println("Error al crear el archivo en la ruta. Por favor introduce una ruta válida.")
	} else {
		reader := bytes.NewReader(content)
		io.Copy(file, reader)
	}
}

func descargarArchivo(conn *tls.Conn, files []FileS) {

	var posicion int
	var ruta string

	println("Introduce la posicion del archivo a descargar: ")
	fmt.Scan(&posicion)
	file := FileS{}
	for index, r := range files {
		if index == posicion {
			file = r
		}
	}
	if file.Peso == 0 {
		println("No tienes archivos para descargar. Introduce alguno para ello.")
	} else {
		println("Introduce la ruta de la carpeta donde quieres que se guarde el archivo (acabada en \\): ")
		fmt.Scan(&ruta)

		almacenarArchivo(file, ruta)
	}

}

func client(ip string, port string) {
	// desactivamos la comprobación del certificado (útil en desarrollo con certificado autofirmado)
	cfg := &tls.Config{InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", ip+":"+port, cfg) // llamamos al servidor con esa configuración
	checkErrorCliente(err)

	defer conn.Close() // es importante cerrar la conexión al finalizar

	fmt.Println("conectado a ", conn.RemoteAddr())

	salida := "-1"
	fmt.Println("Bienvenido a tu Sistema de archivos seguro!")
	for salida != "0" {

		salida = menu()
		if salida == "1" && token == "" {
			user := iniciarSesion() //Iniciamos sesion
			enc := json.NewEncoder(conn)
			enc.Encode(user) //Tiramos mensaje encoded a la conexión

			dec := json.NewDecoder(conn)
			var resp RespuestaS
			dec.Decode(&resp) // Recibimos la respuesta
			fmt.Println(resp.Msg)
			if resp.ActAny != -1 {
				token = strconv.Itoa(resp.ActAny)
			}
		} else if salida == "2" && token == "" {
			user := registro()
			if user.Action != -1 {
				enc := json.NewEncoder(conn)
				enc.Encode(user)

				dec := json.NewDecoder(conn)
				var resp RespuestaS
				dec.Decode(&resp)
				fmt.Println(resp.Msg)
			} else {
				fmt.Println(user)
			}
		} else if token != "" {
			if salida == "1" {
				ids := llamadaConsultar(conn, 4)
				ids = ids
			} else if salida == "2" {

				archivoInfo := añadirArchivo(conn) //Añadimos archivo
				enc := json.NewEncoder(conn)
				enc.Encode(archivoInfo) //Tiramos mensaje encoded a la conexión

				dec := json.NewDecoder(conn)
				var resp RespuestaS
				dec.Decode(&resp)
				fmt.Println(resp.Msg)
			} else if salida == "3" {
				ids := llamadaConsultar(conn, 5)
				descargarArchivo(conn, ids)
			} else if salida == "4" {
				ids := llamadaConsultar(conn, 6)
				file := eliminarArchivo(ids) //se le pasa el DataS con el file
				if file.User.Archivo.Peso != -1 {
					fmt.Println("no entra")
					enc := json.NewEncoder(conn)
					enc.Encode(file)
					dec := json.NewDecoder(conn)
					var resp RespuestaS
					dec.Decode(&resp)
				}

			} else if salida == "5" {
				fmt.Println("Has cerrado sesion correctamente. Esperamos que vuelvas pronto. :( ")
				token = ""
			}
		}
	}
}

func Client(ip string, port string) {

	client(ip, port)
}
