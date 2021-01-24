package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

type App struct {
	Router *mux.Router
	DB     *sql.DB
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
	a.Router.HandleFunc("/profile", a.saveProfile).Methods("POST")
	a.Router.HandleFunc("/login", a.login).Methods("POST")
	a.Router.HandleFunc("/forgot", a.forgot).Methods("POST")
	a.Router.HandleFunc("/reset", a.reset).Methods("POST")
	a.Router.HandleFunc("/auth/google/callback", a.googleCallback).Methods("GET")
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
	Email    string `json:"email"`
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
	res, err := query.Exec(email, passwordHash, fullname, address)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"id": id})
}
func (a *App) getProfile(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]
	log.Println("getProfile:", id)
	row := a.DB.QueryRow(`SELECT id, fullname, email, address, phonenumber, google_auth FROM user WHERE id = ?`, id)
	var userId, googleAuth int
	var fullname, email, address, phonenumber string
	err := row.Scan(&userId, &fullname, &email, &address, &phonenumber, &googleAuth)
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
		"id":          userId,
		"fullname":    fullname,
		"email":       email,
		"address":     address,
		"phoneNumber": phonenumber,
		"google_auth": googleAuth,
	}

	respondWithJSON(w, http.StatusOK, data)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	log.Println("POST /login")
	email := r.FormValue("email")
	password := r.FormValue("password")
	row := a.DB.QueryRow(`SELECT id, password FROM user WHERE email = ?`, email)
	var userId int
	var passwordHash string
	err := row.Scan(&userId, &passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "user not found")
			return
		} else {
			log.Println(err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
			return
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		respondWithError(w, http.StatusForbidden, "password incorrect")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"id": userId, "email": email})
}

const ClientId = "693851654174-2rpkkd7gp95brtf90cofsg4mcj4mkaiq.apps.googleusercontent.com"
const ClientSecret = "0tKreN72PjKDuZmMM7E3UdX5"
const RedirectUri = "http://localhost/auth/google/callback"
const ResponseType = "code"
const SCOPE = "profile email"

func (a *App) googleCallback(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	code := v.Get("code")
	redirect_uri := v.Get("redirect_uri")

	log.Printf("code: %s", code)
	tokenUrl := "https://oauth2.googleapis.com/token"
	log.Printf("accessing token")

	form := url.Values{}
	form.Set("client_id", ClientId)
	form.Set("client_secret", ClientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirect_uri)
	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	type TokenResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	var data TokenResponse
	if resp.StatusCode != 200 {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s", bodyBytes)
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("access_token: %s", data.AccessToken)
	log.Printf("scope: %s", data.Scope)

	//full name, address, telephone, and email

	log.Printf("getting userinfo")
	profileUrl := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err = http.NewRequest("GET", profileUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+data.AccessToken)
	resp, err = hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	//bodyBytes, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Printf("%s", bodyBytes)

	type UserInfo struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	var user UserInfo
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%s", user)
	log.Printf("name: %s", user.Name)
	log.Printf("email: %s", user.Email)

	// check if user exists
	row := a.DB.QueryRow("SELECT id FROM user WHERE email = ?", user.Email)
	var currentId int
	err = row.Scan(&currentId)
	if err != nil && err != sql.ErrNoRows {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	if currentId != 0 {
		// user exists
		log.Printf("user exists")
		respondWithJSON(w, http.StatusOK, map[string]interface{}{"id": currentId})
		return
	}

	// save to db
	query, err := a.DB.Prepare("INSERT INTO user(email, fullname, google_auth) VALUES (?,?,?)")
	if err != nil {
		log.Fatal(err)
	}
	res, err := query.Exec(user.Email, user.Name, true)
	if err != nil {
		log.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("inserting data...")
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"id": id})
}

func (a *App) saveProfile(w http.ResponseWriter, r *http.Request) {
	log.Println("saving user profile")
	id := r.FormValue("id")
	googleAuth := r.FormValue("google_auth")
	email := r.FormValue("email")
	fullname := r.FormValue("fullname")
	address := r.FormValue("address")
	phonenumber := r.FormValue("phonenumber")

	if googleAuth == "1" {
		query, err := a.DB.Prepare("UPDATE user SET fullname = ?, address = ?, phonenumber = ? WHERE id = ?")
		if err != nil {
			log.Fatal(err)
		}
		query.Exec(fullname, address, phonenumber, id)
	} else {
		query, err := a.DB.Prepare("UPDATE user SET fullname = ?, address = ?, phonenumber = ?, email = ? WHERE id = ?")
		if err != nil {
			log.Fatal(err)
		}
		query.Exec(fullname, address, phonenumber, email, id)
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "success"})

}

func (a *App) forgot(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	from := "authgogo@gmail.com"
	pass := "@$#12345678"
	to := email
	hash := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s", time.Now().Format("20060102150405")))))

	query, err := a.DB.Prepare("UPDATE user SET reset_token = ? WHERE email = ?")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	query.Exec(hash, email)

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Reset Password - Gogoauth\n\n" +
		"Hello, Please follow this link to reset password http://localhost:8080/reset/" + hash

	err = smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "success"})
}
func (a *App) reset(w http.ResponseWriter, r *http.Request) {
	log.Println("POST /reset")
	token := r.FormValue("token")
	password := r.FormValue("password")
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	query, err := a.DB.Prepare("UPDATE user SET password = ? WHERE reset_token = ?")
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	_, err = query.Exec(passwordHash, token)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "success"})
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]interface{}{"error": true, "message": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
