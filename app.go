package main

import (
	"fmt"
	"log"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"html/template"
	"net/http"
	"golang.org/x/crypto/bcrypt"
	"encoding/json"
)

type App struct {
	Router *mux.Router
	DB *sql.DB
}

func (a *App) Init(user, pass, dbname, dbhost string) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", user, pass, dbhost, dbname)
	var err error
	a.DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	err = a.DB.Ping()
	if err != nil {
		log.Fatal(err)
	}

	a.Router = mux.NewRouter()
	a.initRoutes()
}
func (a *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, a.Router))
}

func (a *App) initRoutes() {
	a.Router.HandleFunc("/", a.home).Methods("GET")
	a.Router.HandleFunc("/register", a.register).Methods("POST")
	a.Router.HandleFunc("/profile/{id}", a.getProfile).Methods("GET")
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	log.Println("GET /")
	t, err := template.ParseFiles("home.html")
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Fatal(err)
	}
}


type NewUser struct {
	Email string `json:"email"`
	Password string `json:"password"`
}
func (a *App) register(w http.ResponseWriter, r *http.Request) {
	log.Println("POST /register")
	email := r.FormValue("email")
	password := r.FormValue("password")
	fullname := r.FormValue("fullname")
	address := r.FormValue("address")
	if email == "" || password == "" {
		log.Println("empty email/password")
		respondWithError(w, http.StatusBadRequest, "email/password can't be empty")
		return
	}
	log.Printf("email: %s password: %s", email, password)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	query, err := a.DB.Prepare("INSERT INTO user (email, password, fullname, address) VALUES (?,?,?,?)")
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	query.Exec(email, passwordHash, fullname, address)

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"error": false, "message":"user registered successfully"})
}
func (a *App) getProfile(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]
	log.Println("getProfile:", id)
	row := a.DB.QueryRow(`SELECT id, fullname, email, address, phonenumber FROM user WHERE id = ?`, id)
	var userId int
	var fullname, email, address, phonenumber string
	err := row.Scan(&userId, &fullname, &email, &address, &phonenumber)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "not found")
			return
		} else {

                log.Println(err)
                respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}
	}

	data := map[string]interface{}{
		"id":userId,
		"fullname":fullname,
		"email":email,
		"address":address,
		"phoneNumber":phonenumber,
	}

	respondWithJSON(w, http.StatusOK, data)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]interface{}{"error" : true, "message" : message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
