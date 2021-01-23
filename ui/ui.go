package main

import (
	"github.com/gorilla/mux"
	"log"
	"html/template"
	"net/http"
)

type App struct {
	Router *mux.Router
}

func main() {
	app := App{}
	app.Init()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("UI Listening on :8080...")
	app.Run(":8080")
}

func (a *App) Init(){
	a.Router = mux.NewRouter()
	a.initRoutes()
}

func (a *App) Run(addr string){
	log.Fatal(http.ListenAndServe(addr, a.Router))
}

func (a *App) initRoutes() {
	a.Router.HandleFunc("/", a.login).Methods("GET")
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("home.html")
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Fatal(err)
	}
}

