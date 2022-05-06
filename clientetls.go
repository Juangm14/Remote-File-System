package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
)

func msg(valor int, user string) string {
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
		password = string(hashPassword([]byte(password)))
	}

	key := []byte(password[0:16])
	nameEnc, _ := AesEncrypt([]byte(name), key)
	print(nameEnc)

	return "1#" + string(nameEnc) + "|" + password
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

	key := []byte(hashPassword[0:16])
	nameEnc, err := AesEncrypt([]byte(name), key)
	print(err)

	return "2#" + string(nameEnc) + "|" + password
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

			numero, _ := strconv.Atoi(strings.TrimSpace(netscan.Text()))

			_, user = splitFunc(user)
			fmt.Println("servidor: " + msg(numero, user))

		} else if salida == "2" {
			user := registro()
			if user != "Has salido correctamente" {
				netscan := bufio.NewScanner(conn)
				fmt.Fprintln(conn, user) // enviamos la entrada al servidor
				netscan.Scan()           // escaneamos la conexión (se bloquea hasta recibir información)
				fmt.Println("servidor: " + netscan.Text())
			} else {
				fmt.Println(user)
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
