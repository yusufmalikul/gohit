/*
backend service starts here
*/
package main

import (
	"github.com/gorilla/mux"
	"gohit/pkg/database"
	"gohit/pkg/handler"
	"log"
	"net/http"
	"os"
)

type Env struct {
	Router *mux.Router
	Port   string
	DB     database.BaseHandler
}

func main() {
	env := Setup()
	log.Print("Listening on ", env.Port)
	env.Run(":" + env.Port)
}

// Setup database and mux
func Setup() Env {

	port := "80" // set default port to listen

	// needed in heroku environment
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	env := Env{
		Router: mux.NewRouter(),
		DB: database.New(
			os.Getenv("APP_DBUSER"),
			os.Getenv("APP_DBPASS"),
			os.Getenv("APP_DBNAME"),
			os.Getenv("APP_DBHOST"),
		),
		Port: port,
	}

	return env
}

// Run Listen to addr
func (env *Env) Run(addr string) {
	handler.InitRoutes(env.Router, env.DB)
	log.Fatal(http.ListenAndServe(addr, env.Router))
}
