/*
Práctica SC 23/24

Main

Uso básico:
go run sc-general

*/

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func main() {

	fmt.Println("Práctica SC 23/24")
	c := make(chan int)  // canal para sincronizar ambas gorutinas
	c2 := make(chan int) // canal para esperar inicio del servidor
	go func() {
		var datos db
		datos.AccionPreStart()
		c2 <- 1
		server(datos) // lanzamos el servidor en paralelo

		fmt.Println("...servidor terminado.")
		c <- 1 // señalizamos la finalización del servidor
	}()
	go func() { // lanzamos el cliente en paralelo
		<-c2
		client()
		fmt.Println("...cliente terminado.")
		c <- 1 // señalizamos la finalización del cliente
	}()
	<-c // leemos dos veces para esperar a ambas gorutinas
	<-c // en definitiva, a que termine tanto cliente como servidor
}

/****

COMUNICACIÓN

****/

// gestiona el modo servidor
func server(datos db) {
	fmt.Println("Iniciando servidor...")

	// escuchamos el puerto 10443 con https y comprobamos el error
	srv := &http.Server{
		Addr: ":10443",
	}
	// asignamos un handler global que responderá a las peticiones del cliente
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()                              // es necesario procesar el formulario
		w.Header().Set("Content-Type", "text/plain") // cabecera estándar

		datos.AccionPreCommando(w, req)

		usr := req.Form.Get("usr")
		pass := req.Form.Get("pass")
		token := req.Form.Get("token")

		if !datos.puedeAcceder(usr, pass, token, req.Form.Get("cmd")) {
			fmt.Fprintf(w, "ERROR_LOGIN: No es posible acceder a la sección indicada con el usuario y contraseña especificado (%s)\n", req.Form.Get("login"))
			return
		}

		//Este código solo se ejecuta si el usuario está correctamente identificado
		switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
		case "BD_INI": // Inicialización de BD
			datos.Pacs = make(map[uint]paciente)
			datos.Docs = make(map[uint]doctor)
			datos.Hists = make(map[uint]historial)
			datos.Creds = make(map[string]auth)

			datos.registrarUsuario(usr, pass)
			fmt.Fprint(w, "BD_INI: base de datos inicializada.")

		case "LOGIN":
			var token string
			token = datos.GetUserToken(usr)
			fmt.Fprint(w, token)

		case "DOC_REG": // Registro de Doctor
			var doc doctor
			id, _ := strconv.Atoi(req.Form.Get("id"))
			doc.ID = uint(id)
			doc.Nombre = req.Form.Get("nombre")
			doc.Apellidos = req.Form.Get("apellidos")
			doc.Especialidad = req.Form.Get("especialidad")
			doc.Login = req.Form.Get("login")

			_, ok := datos.Creds[doc.Login]
			if ok {
				fmt.Fprint(w, "DOC_REG: usuario ya registrado.")
				break
			}

			datos.Docs[doc.ID] = doc
			if !datos.registrarUsuario(doc.Login, req.Form.Get("contraseña")) {
				fmt.Fprint(w, "DOC_REG: error en la autentificación de usuario.")
				break
			}

			fmt.Fprintf(w, "DOC_REG: doctor [%s] registrado.", doc.Login)

		case "PAC_REG": // Registro de paciente
			var pac paciente
			id, _ := strconv.Atoi(req.Form.Get("id"))
			pac.ID = uint(id)
			pac.Nombre = req.Form.Get("nombre")
			pac.Apellidos = req.Form.Get("apellidos")
			pac.Nacimiento, _ = time.Parse("2000-Jan-01", req.Form.Get("nacimiento"))
			pac.Sexo = req.Form.Get("sexo")
			datos.Pacs[pac.ID] = pac

			fmt.Fprintf(w, "PAC_REG: paciente [%s, %s] registrado.", pac.Apellidos, pac.Nombre)

		case "HIST_REG": // Registro de historial
			var hist historial
			docid, _ := strconv.Atoi(req.Form.Get("doctor"))
			pacid, _ := strconv.Atoi(req.Form.Get("paciente"))
			hist.Doctor = uint(docid)
			hist.Paciente = uint(pacid)
			hist.Datos = req.Form.Get("datos")
			hist.Fecha = time.Now()
			hist.ID = uint(len(datos.Hists) + 1)

			datos.Hists[hist.ID] = hist

			fmt.Fprintf(w, "HIST_REG: historial [%d] registrado.", hist.ID)

		case "BD_GRABAR": // Grabar BD
			datos.guardar(req.Form.Get("fichero"), datos.ClaveMaestra())
			fmt.Fprintf(w, "BD_GRABAR: base de datos grabada en [%s].", req.Form.Get("fichero"))

		case "BD_CARGAR": // Cargar BD
			datos.cargar(req.Form.Get("fichero"), datos.ClaveMaestra())
			fmt.Fprintf(w, "BD_CARGAR: base de datos cargada desde [%s].", req.Form.Get("fichero"))

		case "BD_IMP": // Imprimir BD
			fmt.Println("BASE DE DATOS:")
			fmt.Println(datos)
			fmt.Fprint(w, "BD_IMP: base de datos impresa.")

		case "SALIR": // Salir
			fmt.Fprint(w, "SALIR: Cerrando servidor")
			datos.AccionPreStop()
			srv.Close()

		default:
			datos.CommandosExtras(w, req)
		}

		datos.AccionPostCommando(w, req)
	})

	srv.ListenAndServeTLS("cert.pem", "key.pem")
}

// gestiona el modo cliente
func client() {

	fmt.Println("Iniciando cliente...")

	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Transport: tr}

	switch tipoUI() {
	case 0:
		// ** test basico
		cmdTestServer(cli)
	case 1:
		// ** Programa interactivo linea de comandos
		cmdIniIUI(cli)
	case 2:
		// ** Programa interactivo Intefaz gráfica
		cmdIniGUI(cli)
	}

}

// *** Comandos del cliente
var clienteData dataCliente

func cmdTestServer(cli *http.Client) {

	//Todas estas pruebas se van a realizar con el usuario Admin
	clienteData = dataCliente{
		usrActual:   "Admin",
		tokenActual: "",
	}

	clienteData.passActual = clienteData.ClaveAdminInicial()

	// Inicializar BD
	cmdBDIni(cli)

	// Doctores
	cmdDocReg(cli, "1", "JUAN", "GOMEZ LOPEZ", "General", "jgomez", "1234")
	cmdDocReg(cli, "2", "PEDRO", "PEREZ SANCHEZ", "Oncología", "pperez", "*/--./1")
	cmdDocReg(cli, "3", "MARIA", "ROMERO MARTINEZ", "Traumatología", "aromero", "abcdefgh")

	// Añadir paciente
	cmdPacReg(cli, "1", "LUIS", "ALVAREZ PIQUERAS", "1961-Apr-05", "H")
	cmdPacReg(cli, "2", "SUSANA", "JEMEZ CAMPO", "1978-Jan-15", "M")
	cmdPacReg(cli, "3", "LAURA", "GRANDA PEREZ", "1989-Dec-16", "M")

	// Añadir historial
	cmdHistReg(cli, "1", "1", "Visita de seguimiento")
	cmdHistReg(cli, "1", "2", "Ferritina alta, se deriva a medicina interna")
	cmdHistReg(cli, "2", "3", "Remisión completa")
	cmdHistReg(cli, "3", "1", "Posible hernia lumbar")

	// Grabar y volver a cargar la BD
	cmdBDGrabar(cli, "datos.db")
	cmdBDCargar(cli, "datos.db")

	// Imprimir la BD
	cmdBDImp(cli)

	// Comando no implementado
	data := url.Values{}
	data.Set("cmd", "TEST")
	post(cli, data)

	// Terminar
	cmdSalir(cli)
}

func cmdBDIni(cli *http.Client) {
	// Inicializar la BD
	data := url.Values{}      // estructura para contener los valores
	data.Set("cmd", "BD_INI") // comando (string)
	post(cli, data)
}

func cmdBDGrabar(cli *http.Client, fichero string) {
	data := url.Values{}         
	data.Set("cmd", "BD_GRABAR")
	data.Set("fichero", fichero)
	post(cli, data)
}

func cmdBDCargar(cli *http.Client, fichero string) {
	data := url.Values{}         // estructura para contener los valores
	data.Set("cmd", "BD_CARGAR") // comando (string)
	data.Set("fichero", fichero)
	post(cli, data)
}

func cmdBDImp(cli *http.Client) {
	data := url.Values{}      // estructura para contener los valores
	data.Set("cmd", "BD_IMP") // comando (string)
	post(cli, data)
}

func cmdDocReg(cli *http.Client, id, nombre, apellidos, especialidad, login, contraseña string) {
	// Registrar doctor
	data := url.Values{}       // estructura para contener los valores
	data.Set("cmd", "DOC_REG") // comando (string)
	data.Set("id", id)
	data.Set("nombre", nombre)
	data.Set("apellidos", apellidos)
	data.Set("especialidad", especialidad)
	data.Set("login", login)
	data.Set("contraseña", contraseña)
	post(cli, data)
}

func cmdPacReg(cli *http.Client, id, nombre, apellidos, nacimiento, género string) {
	data := url.Values{}       // estructura para contener los valores
	data.Set("cmd", "PAC_REG") // comando (string)
	data.Set("id", id)
	data.Set("nombre", nombre)
	data.Set("apellidos", apellidos)
	data.Set("nacimiento", nacimiento)
	data.Set("género", género)
	post(cli, data)
}

func cmdHistReg(cli *http.Client, doctor, paciente, datos string) {
	data := url.Values{}        // estructura para contener los valores
	data.Set("cmd", "HIST_REG") // comando (string)
	data.Set("doctor", doctor)
	data.Set("paciente", paciente)
	data.Set("datos", datos)
	post(cli, data)
}

func cmdSalir(cli *http.Client) {
	data := url.Values{}     // estructura para contener los valores
	data.Set("cmd", "SALIR") // comando (string)

	//autenticamos todas las peticiones
	data.Set("usr", clienteData.UserActual())

	if clienteData.TokenActual() != "" {
		data.Set("token", clienteData.TokenActual())
	} else {
		data.Set("pass", clienteData.ClaveActual())
	}
	cli.PostForm("https://localhost:10443", data) // enviamos por POST
}

func post(cli *http.Client, data url.Values) {

	//autenticamos todas las peticiones
	data.Set("usr", clienteData.UserActual())

	if clienteData.TokenActual() != "" {
		data.Set("token", clienteData.TokenActual())
	} else {
		data.Set("pass", clienteData.ClaveActual())
	}

	r, err := cli.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	fmt.Print("Respuesta --> ")
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
}
