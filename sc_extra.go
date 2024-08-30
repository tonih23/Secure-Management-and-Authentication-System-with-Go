/*
Práctica SC 22/23

# Funcionalidad a implementar

Estudiante: (nombre y apellidos aquí)
*/
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/scrypt"
	//"github.com/zserge/lorca" //Para usar IU. Primero descargar lorca con: go get github.com/zserge/lorca
)

/************************
CONFIGURACION PRÁCTICA
*************************/

// Indica el tipo de interfaz que usará la aplicación:
// 0: solo test
// 1: Linea de comandos
// 2: Interfaz gráfica
func tipoUI() int {
	return 1
}

/**********************
FUNCIONES A IMPLEMENTAR
***********************/

/**********************
-------SERVIDOR--------
***********************/
////////PRIMERA PREGUNTA//////////////////////////////////////////////////////////////////
// Guarda la base de datos en un fichero de disco con cifrado y compresión
func (dSrv *db) guardar(nomFich string, clave []byte) {
	iv := make([]byte, aes.BlockSize)
	_, err := os.Stat("vector_inicializacion.txt")
	if os.IsNotExist(err) {
		_, err := rand.Read(iv)
		if err != nil {
			panic(fmt.Errorf("error al generar el IV aleatorio: %v", err))
		}
		err = os.WriteFile("vector_inicializacion.txt", iv, 0644)
		if err != nil {
			panic(fmt.Errorf("error al guardar el IV en el archivo: %v", err))
		}
	} else {
		ivRead, err := os.ReadFile("vector_inicializacion.txt")
		if err != nil {
			panic(fmt.Errorf("error al leer el IV desde el archivo: %v", err))
		}
		if len(ivRead) != aes.BlockSize {
			panic("El IV debe tener 16 bytes")
		}
		iv = ivRead
	}
	b, err := json.Marshal(dSrv)
	chk(err)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err = zw.Write(b)
	chk(err)
	err = zw.Close()
	chk(err)
	bloqueCifrado, err := aes.NewCipher(clave)
	chk(err)
	stream := cipher.NewCTR(bloqueCifrado, iv)
	cifrado := make([]byte, buf.Len())
	stream.XORKeyStream(cifrado, buf.Bytes())
	err = os.WriteFile(nomFich, cifrado, 0777)
	chk(err)
}

// Carga la base de datos de un fichero de disco con descifrado y descompresión
func (dSrv *db) cargar(nomFich string, clave []byte) error {
	cifrado, err := os.ReadFile(nomFich)
	if err != nil {
		return fmt.Errorf("error al leer el archivo cifrado: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	_, err = os.Stat("vector_inicializacion.txt")
	if os.IsNotExist(err) {
		_, err := rand.Read(iv)
		if err != nil {
			return fmt.Errorf("error al generar el IV aleatorio: %v", err)
		}
		err = os.WriteFile("vector_inicializacion.txt", iv, 0644)
		if err != nil {
			return fmt.Errorf("error al guardar el IV en el archivo: %v", err)
		}
	} else {
		ivRead, err := os.ReadFile("vector_inicializacion.txt")
		if err != nil {
			return fmt.Errorf("error al leer el IV desde el archivo: %v", err)
		}
		if len(ivRead) != aes.BlockSize {
			return fmt.Errorf("el IV debe tener 16 bytes")
		}
		iv = ivRead
	}
	bloqueCifrado, err := aes.NewCipher(clave)
	if err != nil {
		return fmt.Errorf("error al crear el bloque de cifrado: %v", err)
	}
	stream := cipher.NewCTR(bloqueCifrado, iv)
	comprimido := make([]byte, len(cifrado))
	stream.XORKeyStream(comprimido, cifrado)
	b := bytes.NewBuffer(comprimido)
	zr, err := zlib.NewReader(b)
	if err != nil {
		return fmt.Errorf("error al crear el lector de zlib: %v", err)
	}
	var resultado bytes.Buffer
	_, err = io.Copy(&resultado, zr)
	if err != nil {
		return fmt.Errorf("error al copiar los datos descomprimidos: %v", err)
	}
	err = zr.Close()
	if err != nil {
		return fmt.Errorf("error al cerrar el lector de zlib: %v", err)
	}
	err = json.Unmarshal(resultado.Bytes(), dSrv)
	if err != nil {
		return fmt.Errorf("error al deserializar los datos: %v", err)
	}
	fmt.Println("")
	return nil
}

////////////////////////////////////////////////////////////////

// Realiza el registro de usuario
func (dSrv *db) registrarUsuario(login, contr string) bool {
	sal := make([]byte, 16)
	_, err := rand.Read(sal)
	chk(err)
	hash, err := scrypt.Key([]byte(contr), sal, 16384, 8, 1, 32)
	chk(err)
	dSrv.Creds[login] = auth{
		Login: login,
		Salt:  sal,
		Hash:  hash[:],
	}
	return true
}

// Autenticación según la sección del API a la que se quiere acceder
func (dSrv *db) puedeAcceder(login, contr string, token string, comando string) bool {
	fmt.Printf("Intento de acceso a comando %s por usuario: %s\n", comando, login)
	if token != "" {
		claim, tokenValid := validar(token)
		if tokenValid && claim.Id == login {
			if comando == "SALIR" || comando == "DOC_REG" {
				return login == dSrv.UserAdmin()
			}
			return true
		}
	}
	// Acceso especial para el administrador sin usuario en la base de datos
	usuario, existe := dSrv.Creds[login]
	if login == dSrv.UserAdmin() && contr == dSrv.ClaveAdminInicial() && (comando == "BD_INI" || comando == "LOGIN") && !existe {
		return true
	}
	if !existe {
		fmt.Println("Usuario no encontrado.")
		return false
	}
	hashEntrada, _ := scrypt.Key([]byte(contr), usuario.Salt, 16384, 8, 1, 32)
	if bytes.Equal(hashEntrada[:], usuario.Hash) {
		if comando == "SALIR" || comando == "DOC_REG" {
			return login == dSrv.UserAdmin() //Si no es el admin devuelve FALSE
		}
		return true
	}
	fmt.Println("Acceso denegado.")
	return false
}

var basedatos = false

// AccionPreStart modificado para generar la clave maestra de cifrado.
func (dSrv *db) AccionPreStart() {
	for {
		fmt.Println("Introduce la contraseña de la base de datos:")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		contraseña := scanner.Text()
		hash := sha256.Sum256([]byte(contraseña))
		dSrv.claveMaestra = hash[:]
		// Cargar la base de datos si existe
		_, err := os.Stat("datos.db")
		if err == nil {
			erro := dSrv.cargar("datos.db", dSrv.claveMaestra)
			if erro == nil {
				basedatos = true
				break
			} else {
				fmt.Println("Contraseña incorrecta. Inténtalo de nuevo.")
			}
		} else {
			break
		}
	}
	// Genera una clave aleatoria
	claveAdmin := make([]byte, 16)
	_, err := rand.Read(claveAdmin)
	chk(err)
	claveAdminInicial = base64.StdEncoding.EncodeToString([]byte(claveAdmin))
	err = os.WriteFile("clave_admin_inicial.txt", []byte(claveAdminInicial), 0600)
	chk(err)
}

// Acciones a ejecutar antes de realizar un comando
func (dSrv *db) AccionPreCommando(w http.ResponseWriter, req *http.Request) {
	//...
}

// Manejador de commandos extras
func (dSrv *db) CommandosExtras(w http.ResponseWriter, req *http.Request) {
	// Obtener el comando desde la solicitud del cliente
	cmd := req.Form.Get("cmd")
	usr := req.Form.Get("usr") // Obtener el usuario de la solicitud

	// Comprobar el comando recibido
	switch cmd {
	// Otros casos...
	case "BONITO":
		fmt.Fprintf(w, "BASE DE DATOS:\n")
		if usr == dSrv.UserAdmin() {
			// Si es Admin, mostrar todo
			table := tablewriter.NewWriter(w)
			table.SetHeader([]string{"ID", "Nombre", "Apellidos", "Especialidad", "Usuario"})
			fmt.Fprintf(w, "------------------DOCTORES-----------------\n")

			// Ordenar doctores por ID
			var doctores []doctor
			for _, doc := range dSrv.Docs {
				doctores = append(doctores, doc)
			}
			sort.Slice(doctores, func(i, j int) bool { return doctores[i].ID < doctores[j].ID })

			for _, doctor := range doctores {
				table.Append([]string{
					fmt.Sprintf("%d", doctor.ID),
					doctor.Nombre,
					doctor.Apellidos,
					doctor.Especialidad,
					doctor.Login,
				})
			}
			table.Render()
		}

		fmt.Fprintf(w, " \n")
		tablePa := tablewriter.NewWriter(w)
		tablePa.SetHeader([]string{"ID", "Nombre", "Apellidos", "Nacimiento", "Sexo"})
		fmt.Fprintf(w, "------------------PACIENTES---------------------------\n")

		// Ordenar pacientes por ID
		var pacientes []paciente
		for _, pac := range dSrv.Pacs {
			pacientes = append(pacientes, pac)
		}
		sort.Slice(pacientes, func(i, j int) bool { return pacientes[i].ID < pacientes[j].ID })

		for _, paciente := range pacientes { // Usar la lista ordenada
			tablePa.Append([]string{
				fmt.Sprintf("%d", paciente.ID),
				paciente.Nombre,
				paciente.Apellidos,
				paciente.Nacimiento.Format("02/01/2006"),
				paciente.Sexo,
			})
		}
		tablePa.Render()

		fmt.Fprintf(w, " \n")
		tableH := tablewriter.NewWriter(w)
		tableH.SetHeader([]string{"ID", "Fecha", "Doctor", "Paciente", "Datos"})
		fmt.Fprintf(w, "------------------HISTORIALES----------------------------\n")

		// Ordenar historiales por ID
		var historiales []historial
		for _, hist := range dSrv.Hists {
			historiales = append(historiales, hist)
		}
		sort.Slice(historiales, func(i, j int) bool { return historiales[i].ID < historiales[j].ID })

		for _, historial := range historiales {
			tableH.Append([]string{
				fmt.Sprintf("%d", historial.ID),
				historial.Fecha.Format("02/01/06 15:04:05"),
				fmt.Sprintf("%d", historial.Doctor),
				fmt.Sprintf("%d", historial.Paciente),
				historial.Datos,
			})
		}
		tableH.Render()

	case "LISTADO_DOCTORES":
		table := tablewriter.NewWriter(w)
		fmt.Fprintf(w, " \n")
		table.SetHeader([]string{"ID", "Nombre", "Apellidos", "Especialidad", "Usuario"})
		fmt.Fprintf(w, "------------------DOCTORES-------------------------------\n")

		// Ordenar doctores por ID
		var doctores2 []doctor
		for _, doc := range dSrv.Docs {
			doctores2 = append(doctores2, doc)
		}
		sort.Slice(doctores2, func(i, j int) bool { return doctores2[i].ID < doctores2[j].ID })

		for _, doctor := range doctores2 {
			table.Append([]string{
				fmt.Sprintf("%d", doctor.ID),
				doctor.Nombre,
				doctor.Apellidos,
				doctor.Especialidad,
				doctor.Login,
			})
		}
		table.Render()

	case "CAMBIAR_CONTRASEÑA":
		login := req.Form.Get("login")
		nuevaContraseña := req.Form.Get("contraseña")
		if !dSrv.cambiocontraseña(login, nuevaContraseña) {
			fmt.Fprint(w, "CAMBIA_CONTRASEÑA: error al cambiar la contraseña.\n")
			return
		}
		fmt.Fprintf(w, "CAMBIA_CONTRASEÑA: contraseña cambiada para el usuario %s.\n", login)

	case "PAC_REG_CORR":
		var pac paciente
		pac.Nombre = req.Form.Get("nombre")
		pac.Apellidos = req.Form.Get("apellidos")
		pac.Nacimiento, _ = time.Parse("2006-Jan-02", req.Form.Get("nacimiento"))
		pac.Sexo = req.Form.Get("género")
		pac.ID = uint(len(dSrv.Pacs) + 1)

		dSrv.Pacs[pac.ID] = pac
		fmt.Fprintf(w, "PAC_REG_CORR: paciente [%s, %s] registrado.", pac.Apellidos, pac.Nombre)

	case "LISTA_PACIENTES":
		doctorUsr := req.Form.Get("doctor")
		var doctorID uint
		var doctorFound bool
		for _, doctor := range dSrv.Docs {
			if doctor.Login == doctorUsr {
				doctorID = doctor.ID
				doctorFound = true
				break
			}
		}
		if !doctorFound {
			fmt.Fprintf(w, "Error: No se encontró el doctor con usuario %s.\n", doctorUsr)
			return
		}
		tableH := tablewriter.NewWriter(w)
		tableH.SetHeader([]string{"ID", "Fecha", "Doctor", "Paciente", "Datos"})
		fmt.Fprintf(w, " \n")
		fmt.Fprintf(w, "------------------HISTORIALES DEL DOCTOR----------------------------\n")
		var pacientesIDs []uint
		var historiales []historial
		for _, historial := range dSrv.Hists {
			historiales = append(historiales, historial)
		}
		sort.Slice(historiales, func(i, j int) bool { return historiales[i].ID < historiales[j].ID })
		for _, historial := range historiales {
			if historial.Doctor == doctorID {
				tableH.Append([]string{
					fmt.Sprintf("%d", historial.ID),
					historial.Fecha.Format("02/01/06 15:04:05"),
					fmt.Sprintf("%d", historial.Doctor),
					fmt.Sprintf("%d", historial.Paciente),
					historial.Datos,
				})
				pacientesIDs = append(pacientesIDs, historial.Paciente)
			}
		}
		tableH.Render()
		tablePac := tablewriter.NewWriter(w)
		tablePac.SetHeader([]string{"ID", "Nombre", "Apellidos", "Nacimiento", "Sexo"})
		fmt.Fprintf(w, "------------------PACIENTES DEL DOCTOR----------------------------\n")
		pacientesMap := make(map[uint]struct{})

		for _, pacienteID := range pacientesIDs {
			pacientesMap[pacienteID] = struct{}{}
		}
		var pacientes []paciente
		for _, pac := range dSrv.Pacs {
			pacientes = append(pacientes, pac)
		}
		sort.Slice(pacientes, func(i, j int) bool { return pacientes[i].ID < pacientes[j].ID })
		for _, paciente := range pacientes { // Usar la lista ordenada
			if _, exists := pacientesMap[paciente.ID]; exists {
				tablePac.Append([]string{
					fmt.Sprintf("%d", paciente.ID),
					paciente.Nombre,
					paciente.Apellidos,
					paciente.Nacimiento.Format("02/01/2006"),
					paciente.Sexo,
				})
			}
		}
		tablePac.Render()

	case "HIST_REG_CORR": // Registro de historial AkW39JAkQXVMXlH3tR0haA==  <i3;>R3kxY-K
		var hist historial
		usuario := req.Form.Get("usuario")
		existeIDdoc := false
		var docid uint
		docidInt, _ := strconv.Atoi(req.Form.Get("doctor"))
		if usuario == "Admin" {
			docid = uint(docidInt)
			for _, doctor := range dSrv.Docs {
				if doctor.ID == docid {
					existeIDdoc = true
					hist.Doctor = uint(docid)
					break
				}
			}
		} else {
			for _, doctor := range dSrv.Docs {
				if doctor.Login == usuario {
					docid = doctor.ID
					existeIDdoc = true
					break

				}
			}
		}

		existeIDpac := false
		pacid, _ := strconv.Atoi(req.Form.Get("paciente"))
		for _, paciente := range dSrv.Pacs {
			if paciente.ID == uint(pacid) {
				existeIDpac = true
				break
			}
		}

		if existeIDdoc && existeIDpac {
			hist.Doctor = docid
			hist.Paciente = uint(pacid)
			hist.Datos = req.Form.Get("datos")
			hist.Fecha = time.Now()
			hist.ID = uint(len(dSrv.Hists) + 1)

			dSrv.Hists[hist.ID] = hist

			fmt.Fprintf(w, "HIST_REG_CORR: historial [%d] registrado.", hist.ID)
		} else {
			fmt.Fprintf(w, "HIST_REG_CORR: historial no registrado. Alguno de los IDs no han sido encontrados")
		}

	case "DOC_REG_CORR": // Registro de Doctor
		var doc doctor
		doc.Nombre = req.Form.Get("nombre")
		doc.Apellidos = req.Form.Get("apellidos")
		doc.Especialidad = req.Form.Get("especialidad")
		doc.Login = req.Form.Get("login")
		doc.ID = uint(len(dSrv.Docs) + 1)
		_, ok := dSrv.Creds[doc.Login]
		if ok {
			fmt.Fprint(w, "DOC_REG_CORR: usuario ya registrado.")
			break
		}

		dSrv.Docs[doc.ID] = doc
		if !dSrv.registrarUsuario(doc.Login, req.Form.Get("contraseña")) {
			fmt.Fprint(w, "DOC_REG_CORR: error en la autentificación de usuario.")
			break
		}

		fmt.Fprintf(w, "DOC_REG: doctor [%s] registrado.", doc.Login)

	default:
		// Manejar comandos no reconocidos
		fmt.Fprintf(w, "Comando no reconocido: %s\n", cmd)
	}
}

func cmdDocRegCorr(cli *http.Client, nombre, apellidos, especialidad, login, contraseña string) {
	// Registrar doctor
	data := url.Values{}            // estructura para contener los valores
	data.Set("cmd", "DOC_REG_CORR") // comando (string)
	data.Set("nombre", nombre)
	data.Set("apellidos", apellidos)
	data.Set("especialidad", especialidad)
	data.Set("login", login)
	data.Set("contraseña", contraseña)
	post(cli, data)
}

func cmdListaPacientes(cli *http.Client, doctor string) {
	data := url.Values{}               // estructura para contener los valores
	data.Set("cmd", "LISTA_PACIENTES") // comando (string)
	data.Set("doctor", doctor)         // comando (string)
	post(cli, data)
}

// NUEVA FUNCION CAMBIO DE CONTRASEÑA
func (dSrv *db) cambiocontraseña(login, contr string) bool {
	// Verifica si el usuario existe en la base de datos.
	usuario, existe := dSrv.Creds[login]
	if !existe {
		fmt.Println("Error: Usuario no encontrado.") // Debugging
		return false                                 // Retorna falso para indicar que el usuario no existe.
	}

	// Genera una nueva sal aleatoria de 16 bytes.
	sal := make([]byte, 16)
	_, err := rand.Read(sal)
	if err != nil {
		fmt.Printf("Error al generar la sal: %v\n", err) // Debugging
		return false
	}

	// Combina la nueva contraseña proporcionada y la nueva sal, y luego genera el hash usando scrypt.
	hash, err := scrypt.Key([]byte(contr), sal, 16384, 8, 1, 32)
	if err != nil {
		fmt.Printf("Error al generar el hash: %v\n", err) // Debugging
		return false
	}

	// Actualiza los datos de autenticación del usuario en la base de datos.
	usuario.Salt = sal
	usuario.Hash = hash
	dSrv.Creds[login] = usuario

	return true // Retorna true indicando que la operación fue exitosa.
}

func cmdHistRegCorr(cli *http.Client, doctor, paciente, datos, usr string) {
	data := url.Values{}             // estructura para contener los valores
	data.Set("cmd", "HIST_REG_CORR") // comando (string)
	data.Set("doctor", doctor)
	data.Set("paciente", paciente)
	data.Set("datos", datos)
	data.Set("usuario", usr)
	post(cli, data)
}

func cmdBDBonito(cli *http.Client) {
	data := url.Values{}      // estructura para contener los valores
	data.Set("cmd", "BONITO") // comando (string)
	post(cli, data)
}

func cmdBDListadoDoctores(cli *http.Client) {
	data := url.Values{}                // estructura para contener los valores
	data.Set("cmd", "LISTADO_DOCTORES") // comando (string)
	post(cli, data)
}

func cmdCambioContraseña(cli *http.Client, user string, contra string) {
	data := url.Values{}                  // estructura para contener los valores
	data.Set("cmd", "CAMBIAR_CONTRASEÑA") // comando (string)
	data.Set("login", user)               // Cambiar "usr" a "login"
	data.Set("contraseña", contra)
	post(cli, data)
}

// CORREECCION BUG DEL MAIN (sexo y nacimiento)
func cmdPacRegCorr(cli *http.Client, nombre, apellidos, nacimiento, género string) {
	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "PAC_REG_CORR")
	data.Set("nombre", nombre)
	data.Set("apellidos", apellidos)
	data.Set("nacimiento", nacimiento)
	data.Set("género", género)
	post(cli, data)
}

// Acciones a ejecutar despues de realizar un comando
func (dSrv *db) AccionPostCommando(w http.ResponseWriter, req *http.Request) {
	//...
}

// Acciones a ejecutar antes de apagar el servidor
func (dSrv *db) AccionPreStop() {
	//...
}

// Obtener clave maestra para el cifrado (tamaño de 32 bytes -> 256bits)
// ClaveMaestra modificado para devolver la clave maestra almacenada en la estructura db.
func (dSrv *db) ClaveMaestra() []byte {
	return dSrv.claveMaestra
}

// Obtener clave admin para login
func (dSrv *db) ClaveAdminInicial() string {

	return string(claveAdminInicial)
}

// Obtener nombre usuario admin para login
func (dSrv *db) UserAdmin() string {
	return "Admin"
}

// Obtiene el token actual de un cliente. Cadena vacia si no tiene o está caducado
func (dSrv *db) GetUserToken(usr string) string {
	token := crearToken(usr, 30)
	return token
}

func getSecretoJwt() []byte {
	return []byte("mi-secreto")
}

func crearToken(usuario string, minutos int) string {
	//Tiempo de expiración
	Hours := 0
	Mins := minutos
	Sec := 0

	Claim := Payload{
		usuario,
		time.Now().Local().Add(
			time.Hour*time.Duration(Hours) +
				time.Minute*time.Duration(Mins) +
				time.Second*time.Duration(Sec)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claim)

	mySecret := getSecretoJwt()
	signedToken, err := token.SignedString(mySecret)
	chk(err)

	return signedToken
}

func validar(receivedToken string) (*Payload, bool) {
	// Intenta analizar el token recibido usando la función ParseWithClaims de la librería jwt,
	// pasando el token recibido, una estructura vacía de Payload y una función anónima que retorna la clave secreta.
	token, _ := jwt.ParseWithClaims(receivedToken, &Payload{}, func(token *jwt.Token) (interface{}, error) {
		// Verifica si el método de firma es HMAC (Hash-based Message Authentication Code).
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			// Si el método de firma no es HMAC, retorna un error indicando el método de firma incorrecto.
			return nil, fmt.Errorf("Metodo de firma erroneo: %v", token.Header["alg"])
		}

		// Si el método de firma es correcto, retorna el secreto JWT.
		return getSecretoJwt(), nil
	})

	// Convierte los reclamos del token a la estructura Payload.
	claim, ok := token.Claims.(*Payload)
	// Verifica si la conversión fue exitosa y si el token es válido.
	if ok && token.Valid {
		// Si el token es válido, retorna los reclamos (claim) y true.
		return claim, true
	}

	// Si el token no es válido o la conversión falló, retorna los reclamos (claim) y false.
	return claim, false
}

type Payload struct {
	Id        string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

func (c Payload) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if now > c.ExpiresAt {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired

		return vErr
	} else {
		return nil
	}

}

/**********************
-------CLIENTE--------
***********************/

var claveAdminInicial string

// Obtener clave admin para login en servidor
func (dCli *dataCliente) ClaveAdminInicial() string {
	// Lee la clave desde el archivo
	return string(claveAdminInicial)
	//return "soy la clave inicial de admin"
}

// Devuelve el usuario actual para login en servidor
func (dCli *dataCliente) UserActual() string {
	return dCli.usrActual
}

// Devuelve la clave del usuario actual
func (dCli *dataCliente) ClaveActual() string {
	return dCli.passActual
}

// Devuelve el token de acceso del usuario actual
func (dCli *dataCliente) TokenActual() string {
	return dCli.tokenActual
}

/*
*********
INTERFACES
**********
*/

func cmdLogin(cli *http.Client, usr string, pass string) string {
	data := url.Values{}
	//autenticamos todas las peticiones
	data.Set("usr", usr)
	data.Set("pass", pass)
	data.Set("cmd", "LOGIN") // comando (string)

	var buffer bytes.Buffer

	r, err := cli.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	fmt.Print("Respuesta --> ")
	_, err = io.Copy(&buffer, r.Body)

	retorno := buffer.String()

	return retorno
}
func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// Función que desarrolla la interfaz por linea de comandos en caso de ser este el modo de implemantación
func cmdIniIUI(cli *http.Client) {
mainLoop:
	for {
		accionStr := accionMenuInicial()
		accion, err := strconv.Atoi(accionStr)
		if err != nil {
			fmt.Println("Debe introducir un número válido.")
			continue
		}
		fmt.Println("")
		if accion == 0 {
			break
		}
		switch accion {
		case 1:
			var usr, pass string

			fmt.Println("Usuario:")
			fmt.Scanln(&usr)
			fmt.Println("Contraseña:")
			fmt.Scanln(&pass)

			token := cmdLogin(cli, usr, pass)

			if strings.HasPrefix(token, "ERROR_LOGIN") {
				fmt.Println("Error al hacer login")
				break
			}
			fmt.Println("Iniciando sesión con '" + usr + "' y  contraseña '" + pass + "'")
			clienteData = dataCliente{
				usrActual:   usr,
				passActual:  pass,
				tokenActual: token,
			}
			if !basedatos {
				for {
					accion2Str := accionMenuINI()
					accion2, err := strconv.Atoi(accion2Str)
					if err != nil {
						fmt.Println("Debe introducir un número válido.")
						continue
					}
					fmt.Println("")
					if accion2 == 0 {
						break mainLoop
					} else if accion == 1 {
						token = clienteData.tokenActual
						clienteData = dataCliente{
							usrActual:  usr,
							passActual: pass,
						}
						cmdBDIni(cli)
						cmdBDGrabar(cli, "datos.db")
						clienteData = dataCliente{
							usrActual:   usr,
							passActual:  pass,
							tokenActual: token,
						}
						basedatos = true
						break
					} else {
						fmt.Println("Debe introducir 0 o 1")
					}
				}

			}
			for {
				accion2Str := accionMenuSecundario(usr)
				accion2, err := strconv.Atoi(accion2Str)
				if err != nil {
					fmt.Println("Debe introducir un número válido.")
					continue
				}
				fmt.Println("")
				if accion2 == 0 {
					break
				}
				switch accion2 {
				case 1: //Registrar un paciente
					var nombre, apellidos, fecha, género string

					for {
						fmt.Println("Nombre:")
						nombre = readLine()
						if esAlfabetico(nombre) {
							break
						}
						fmt.Println("El Nombre debe ser alfabético y puede incluir letras, espacios, guiones y caracteres acentuados.")
					}
					for {
						fmt.Println("Apellidos:")
						apellidos = readLine()
						if esAlfabetico(apellidos) {
							break
						}
						fmt.Println("Los Apellidos deben ser alfabéticos y pueden incluir letras, espacios, guiones y caracteres acentuados.")
					}
					for {
						fmt.Println("Fecha de Nacimiento (DD/MM/YYYY):")
						fecha = readLine()
						if esFechaValida(fecha) {
							break
						}
						fmt.Println("La Fecha debe ser existente, estar en el formato DD/MM/YYYY y no ser futura.")
					}
					// Convertir la fecha a formato "2006-Jan-02"
					fechaConvertida, _ := time.Parse("02/01/2006", fecha)
					fechaFormateada := fechaConvertida.Format("2006-Jan-02")

					for {
						fmt.Println("Sexo (Hombre - 'H' / Mujer - 'M'):")
						fmt.Scanln(&género)
						if esGeneroValido(género) {
							break
						}
						fmt.Println("El Género debe ser 'H' para Hombre o 'M' para Mujer.")
					}

					cmdPacRegCorr(cli, nombre, apellidos, fechaFormateada, género)
					cmdBDGrabar(cli, "datos.db")
				case 2: //Añadir un historial
					var idPac, idMed, observaciones string

					fmt.Println("Id Paciente:")
					fmt.Scanln(&idPac)
					if usr == "Admin" {
						fmt.Println("Id Medico:")
						fmt.Scanln(&idMed)
					} else {
						idMed = "-1"

					}

					fmt.Println("Observaciones:")
					observaciones = readLine()

					cmdHistRegCorr(cli, idMed, idPac, observaciones, usr)
					cmdBDGrabar(cli, "datos.db")

				case 3: //Imprimir bonito  nuPhndSh5/xonRRXmmmFXw==
					if usr == "Admin" {
						var doctor, opcion string
						for {
							fmt.Println("Para ver la base dedatos entera pulse 1, para filtrar por doctor pulse 2:")
							fmt.Scanln(&opcion)
							if opcion == "1" {
								cmdBDBonito(cli)
								break
							} else if opcion == "2" {
								cmdBDListadoDoctores(cli)
								fmt.Println("Introduzca el usuario del doctor")
								fmt.Scanln(&doctor)
								cmdListaPacientes(cli, doctor)
								break
							} else {
								fmt.Println("Debe introducir 1 o 2")
							}
						}
					} else {
						cmdListaPacientes(cli, usr)
					}

				case 4: //cambiar contraseña
					if usr == "Admin" {
						var login, num, nueva string
						for {
							fmt.Println("Si quiere cambiar la contraseña Admin escriba 1, si quiere cambiar la de algún doctor escriba 2:")
							fmt.Scanln(&num)
							if num == "1" || num == "2" {
								break
							}
							fmt.Println("Por favor, escriba '1' o '2'.")
						}

						if num == "1" {
							for {
								fmt.Println("Escriba su nueva contraseña:")
								fmt.Scanln(&nueva)
								if esContraseñaSegura(nueva) {
									break
								}
								fmt.Println("La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y caracteres especiales.")
								for {
									fmt.Println("¿Desea generar automáticamente una contraseña segura? (si/no)")
									var opcion string
									fmt.Scanln(&opcion)
									if opcion == "si" {
										nueva = generarContrasenaSegura()
										fmt.Println("Se ha generado automáticamente la siguiente contraseña segura:", nueva)
										break
									} else if opcion == "no" {
										break
									} else {
										fmt.Println("Por favor, escriba 'si' o 'no'.")
									}
								}
								if esContraseñaSegura(nueva) {
									break
								}
							}
							cmdCambioContraseña(cli, "Admin", nueva)
							cmdBDGrabar(cli, "datos.db")

						} else if num == "2" { // Cambiado elif a else if
							cmdBDListadoDoctores(cli)
							fmt.Println("Escriba el nombre de usuario del doctor al que quiere cambiarle la contraseña:")
							fmt.Scanln(&login)
						doctorcontra:
							for {
								fmt.Println("Escriba su nueva contraseña:")
								fmt.Scanln(&nueva)
								if esContraseñaSegura(nueva) {
									break
								}
								fmt.Println("La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y caracteres especiales.")
								for {
									fmt.Println("¿Desea generar automáticamente una contraseña segura? (si/no)")
									var opcion string
									fmt.Scanln(&opcion)
									if opcion == "si" {
										nueva = generarContrasenaSegura()
										fmt.Println("Se ha generado automáticamente la siguiente contraseña segura:", nueva)
										break doctorcontra
									} else if opcion == "no" {
										break
									} else {
										fmt.Println("Por favor, escriba 'si' o 'no'.")
									}
								}
							}
							cmdCambioContraseña(cli, login, nueva)
							cmdBDGrabar(cli, "datos.db")
						}
					} else {
						var contraseña string
						fmt.Println("Escriba su contraseña actual:")
						fmt.Scanln(&contraseña)

						if contraseña == clienteData.passActual {
							var nueva string
						buclemalo:
							for {
								fmt.Println("Escriba su nueva contraseña:")
								fmt.Scanln(&nueva)
								if esContraseñaSegura(nueva) {
									break
								}
								fmt.Println("La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y caracteres especiales.")
								for {
									fmt.Println("¿Desea generar automáticamente una contraseña segura? (si/no)")
									var opcion string
									fmt.Scanln(&opcion)
									if opcion == "si" {
										nueva = generarContrasenaSegura()
										fmt.Println("Se ha generado automáticamente la siguiente contraseña segura:", nueva)
										break buclemalo
									} else if opcion == "no" {
										break
									} else {
										fmt.Println("Por favor, escriba 'si' o 'no'.")
									}
								}
							}
							cmdCambioContraseña(cli, usr, nueva)
							cmdBDGrabar(cli, "datos.db")
						} else {
							fmt.Println("Contraseña incorrecta. No se realizó ningún cambio.")
						}
					}
				case 5: //Registrar un doctor
					if usr == "Admin" {
						var nombre, apellidos, especialidad, us, contra string
						cmdBDListadoDoctores(cli)
						for {
							fmt.Println("Nombre:")
							fmt.Scanln(&nombre)
							if esAlfabetico(nombre) {
								break
							}
							fmt.Println("El Nombre debe ser alfabético y puede incluir letras, espacios, guiones y caracteres acentuados.")
						}
						for {
							fmt.Println("Apellidos:")
							apellidos = readLine()
							if esAlfabetico(apellidos) {
								break
							}
							fmt.Println("Los Apellidos deben ser alfabéticos y pueden incluir letras, espacios, guiones y caracteres acentuados.")
						}
						for {
							fmt.Println("Especialidad:")
							fmt.Scanln(&especialidad)
							if esAlfabetico(especialidad) {
								break
							}
							fmt.Println("La Especialidad debe ser alfabético y puede incluir letras, espacios, guiones y caracteres acentuados.")
						}
						fmt.Println("Usuario:")
						fmt.Scanln(&us)

						for {
							fmt.Println("Contraseña:")
							fmt.Scanln(&contra)
							if esContraseñaSegura(contra) {
								break
							}
							fmt.Println("La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y caracteres especiales.")
							fmt.Println("¿Desea generar automáticamente una contraseña segura? (si/no)")
							var opcion string
							fmt.Scanln(&opcion)
							if opcion == "si" {
								contra = generarContrasenaSegura()
								fmt.Println("Se ha generado automáticamente la siguiente contraseña segura:", contra)
								break
							} else if opcion == "no" {
								continue
							} else {
								fmt.Println("Por favor, escriba 'si' o 'no'.")
							}
						}

						cmdDocRegCorr(cli, nombre, apellidos, especialidad, us, contra)
						cmdBDGrabar(cli, "datos.db")
					} else {
						fmt.Println("Debe seleccionar un número del 0 al 4")
					}

				case 6: //Imprimir Base Datos
					if usr == "Admin" {
						cmdBDImp(cli)
					} else {
						fmt.Println("Debe seleccionar un número del 0 al 4")
					}
				case 7: //Salir
					if usr == "Admin" {
						cmdSalir(cli)
						break mainLoop
					} else {
						fmt.Println("Debe seleccionar un número del 0 al 4 ")
					}
				default:
					if usr == "Admin" {
						fmt.Println("Debe Introducir un número entre 0 y 8 ")
					} else {
						fmt.Println("Debe seleccionar un número del 0 al 4 ")
					}
				}

			}
		default:
			fmt.Println("Debe introducir 0 o 1")
		}
	}

	cmdSalir(cli)
}

// Funciones de validación
func esNumerico(input string) bool {
	_, err := strconv.Atoi(input)
	return err == nil
}

func esAlfabetico(input string) bool {
	// Expresión regular que permite letras (incluyendo acentuadas y con diéresis), espacios y guiones
	re := regexp.MustCompile(`^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s-]+$`)
	return re.MatchString(input)
}

func esFechaValida(input string) bool {
	// Convertir la fecha de "DD/MM/YYYY" a "2006-Jan-02"
	fecha, err := time.Parse("02/01/2006", input)
	if err != nil {
		return false
	}

	// Verificar que la fecha no sea futura
	if fecha.After(time.Now()) {
		return false
	}

	return true
}
func esGeneroValido(input string) bool {
	return input == "M" || input == "H"
}
func esContraseñaSegura(contraseña string) bool {
	// Verificar longitud mínima
	if len(contraseña) < 8 {
		return false
	}
	// Verificar caracteres
	var (
		tieneMayúsculas bool
		tieneMinúsculas bool
		tieneNúmeros    bool
		tieneEspeciales bool
	)
	for _, r := range contraseña {
		switch {
		case unicode.IsUpper(r):
			tieneMayúsculas = true
		case unicode.IsLower(r):
			tieneMinúsculas = true
		case unicode.IsNumber(r):
			tieneNúmeros = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			tieneEspeciales = true
		}
	}
	// Verificar que cumpla con todos los criterios
	return tieneMayúsculas && tieneMinúsculas && tieneNúmeros && tieneEspeciales
}

// Función para generar una contraseña segura
func generarContrasenaSegura() string {
	caracteresValidos := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?~"
	longitud := 12
	contrasena := make([]byte, longitud)
	for i := range contrasena {
		indice, err := rand.Int(rand.Reader, big.NewInt(int64(len(caracteresValidos))))
		if err != nil {
			panic(err) // Manejar el error adecuadamente en tu aplicación
		}
		contrasena[i] = caracteresValidos[indice.Int64()]
	}
	return string(contrasena)
}

func accionMenuInicial() string {
	fmt.Println("")
	fmt.Println("---------------****---------------")
	fmt.Println("Acciones:")
	fmt.Println("1) Login")
	fmt.Println("0) Salir")
	fmt.Println("----------------------------------")
	fmt.Println("¿Qué deseas hacer? (0,1)")

	var opcion string
	fmt.Scanln(&opcion)

	return opcion
}

func accionMenuINI() string {
	fmt.Println("")
	fmt.Println("---------------****---------------")
	fmt.Println("Acciones:")
	fmt.Println("1) Inicializar base de datos")
	fmt.Println("0) Salir")
	fmt.Println("----------------------------------")
	fmt.Println("¿Qué deseas hacer? (0,1)")

	var opcion string
	fmt.Scanln(&opcion)

	return opcion
}

func accionMenuSecundario(usr string) string {
	if usr == "Admin" {

		fmt.Println("")
		fmt.Println("---------------****---------------")
		fmt.Println("Acciones:")
		fmt.Println("1) Registrar un paciente")
		fmt.Println("2) Añadir un historial")
		fmt.Println("3) Imprimir tablas de datos")
		fmt.Println("4) Cambiar contraseña")
		fmt.Println("5) Registrar un doctor")
		fmt.Println("6) Imprimir base de datos")
		fmt.Println("7) Salir")
		fmt.Println("0) Volver")
		fmt.Println("----------------------------------")
		fmt.Println("¿Qué deseas hacer? (0,1,2,3,4,5,6,7)")
	} else {
		fmt.Println("")
		fmt.Println("---------------****---------------")
		fmt.Println("Acciones:")
		fmt.Println("1) Registrar un paciente")
		fmt.Println("2) Añadir un historial")
		fmt.Println("3) Imprimir tablas de datos")
		fmt.Println("4) Cambiar contraseña")
		fmt.Println("0) Volver")
		fmt.Println("----------------------------------")
		fmt.Println("¿Qué deseas hacer? (0,1,2,3,4)")
	}

	var opcion string
	fmt.Scanln(&opcion)

	return opcion
}

// Función que desarrolla la interfaz gráfica en caso de ser este el modo de implemantación
// Recuerda descargar el módulo de go con:
// go get github.com/zserge/lorca
func cmdIniGUI(cli *http.Client) {
	/*
		args := []string{}
		if runtime.GOOS == "linux" {
			args = append(args, "--class=Lorca")
		}
		ui, err := lorca.New("", "", 480, 320, args...)
		if err != nil {
			log.Fatal(err)
		}
		defer ui.Close()

		// A simple way to know when UI is ready (uses body.onload event in JS)
		ui.Bind("start", func() {
			log.Println("UI is ready")
		}) MX0*XJum{U_^

		// Load HTML.
		b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		html := string(b) // convert content to a 'string'
		ui.Load("data:text/html," + url.PathEscape(html))

		// You may use console.log to debug your JS code, it will be printed via
		// log.Println(). Also exceptions are printed in a similar manner.
		ui.Eval(`
			console.log("Hello, world!");
		`)

		// Wait until the interrupt signal arrives or browser window is closed
		sigc := make(chan os.Signal)
		signal.Notify(sigc, os.Interrupt)
		select {
		case <-sigc:
		case <-ui.Done():
		}

		log.Println("exiting...")
	*/
}

/******
DATOS
*******/

// contenedor de la base de datos
type db struct {
	Pacs  map[uint]paciente  // lista de pacientes indexados por ID
	Docs  map[uint]doctor    // lista de doctores indexados por ID
	Hists map[uint]historial // lista de historiales indexados por ID
	Creds map[string]auth    // lista de credenciales indexadas por Login
	//AÑADIDO para gestionar clave maestra
	claveMaestra []byte // Almacenará la clave maestra generada
	claveAdmin   string //guardamos la Clave Admin introducida
}

// datos relativos a pacientes
type paciente struct {
	ID         uint // identificador primario de paciente
	Nombre     string
	Apellidos  string
	Nacimiento time.Time
	Sexo       string //H-> Mombre, M-> Mujer
}

// datos relativos al personal médico
type doctor struct {
	ID           uint // identificador primario del doctor
	Nombre       string
	Apellidos    string
	Especialidad string
	Login        string // referencia a auth
}

// datos relativos a historiales
type historial struct {
	ID       uint      // identificador primario de la entrada de historial
	Fecha    time.Time // fecha de creación/modificación
	Doctor   uint      // referencia a un doctor
	Paciente uint      // referencia a un paciente
	Datos    string    // contenido de la entrada del historial (texto libre)
}

// datos relativos a la autentificación (credenciales)
type auth struct {
	Login string // nombre de usuario
	Salt  []byte // sal para el hash de la contraseña
	Hash  []byte // hash de la contraseña
}

// Estos son los datos que almacena el cliente en memoría para trabajar
type dataCliente struct {
	usrActual   string // nombre de usuario introducido por el usuario
	passActual  string // contraseña introducida por el usuario
	tokenActual string // token proporcionado por el servidor para autenticación de las peticiones
}

/***********
UTILIDADES
************/

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}
