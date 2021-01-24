package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type App struct {
	Router *mux.Router
	ApiUrl string
}

var hashKey = []byte("6v9y$B&E)H@McQfTjWmZq4t7w!z%C*F-")
var s = securecookie.New(hashKey, nil)

func main() {
	app := App{}
	app.Init()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("UI Listening on :8080...")
	app.Run(":8080")
}

func (a *App) Init() {
	a.Router = mux.NewRouter()
	a.ApiUrl = "http://localhost:80"
	a.initRoutes()
}

func (a *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, a.Router))
}

func (a *App) initRoutes() {
	a.Router.HandleFunc("/", a.login).Methods("GET")
	a.Router.HandleFunc("/", a.loginSubmit).Methods("POST")
	a.Router.HandleFunc("/profile", a.profile).Methods("GET")
	a.Router.HandleFunc("/profile", a.saveProfile).Methods("POST")
	a.Router.HandleFunc("/register", a.register).Methods("GET")
	a.Router.HandleFunc("/register", a.saveRegister).Methods("POST")
	a.Router.HandleFunc("/forgot", a.forgot).Methods("GET")
	a.Router.HandleFunc("/forgot", a.forgotSubmit).Methods("POST")
	a.Router.HandleFunc("/reset/{token}", a.reset).Methods("GET")
	a.Router.HandleFunc("/reset/{token}", a.saveReset).Methods("POST")
	a.Router.HandleFunc("/auth/google/login", a.googleLogin).Methods("GET")
	a.Router.HandleFunc("/auth/google/callback", a.googleCallback).Methods("GET")
	a.Router.HandleFunc("/logout", a.logout).Methods("GET")
}

const ClientId = "693851654174-2rpkkd7gp95brtf90cofsg4mcj4mkaiq.apps.googleusercontent.com"
const ClientSecret = "0tKreN72PjKDuZmMM7E3UdX5"
const RedirectUri = "http://localhost:8080/auth/google/callback"
const ResponseType = "code"
const SCOPE = "profile email"

func (a *App) googleCallback(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	code := v.Get("code")
	log.Printf("code: %s", code)

	req, err := http.NewRequest("GET", a.ApiUrl+"/auth/google/callback?code="+code+"&redirect_uri="+RedirectUri, nil)
	if err != nil {
		log.Fatal(err)
	}
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", body)

	if resp.StatusCode != 200 {
		w.Write([]byte("failed"))
	}

	type User struct {
		ID int `json:"id"`
	}

	user := User{}
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}
	// set cookie
	setCookie(w, r, strconv.Itoa(user.ID))
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func (a *App) googleLogin(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=%s&&scope=%s",
		ClientId,
		RedirectUri,
		ResponseType,
		SCOPE,
	),
		http.StatusFound)
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("register.html")
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Fatal(err)
	}
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

func (a *App) forgot(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("forgot.html")
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Fatal(err)
	}
}
func (a *App) forgotSubmit(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	form := url.Values{}
	form.Set("email", email)
	req, err := http.NewRequest("POST", a.ApiUrl+"/forgot", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read response
	if resp.StatusCode == 404 {
		fmt.Fprint(w, "user does not exist.")
		return
	}

	if resp.StatusCode != 200 {
		fmt.Fprint(w, "something went wrong")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Please check your email"))

}

func (a *App) loginSubmit(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	req, err := http.NewRequest("POST", a.ApiUrl+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read response
	if resp.StatusCode == 404 {
		fmt.Fprint(w, "user does not exist.")
		return
	}
	if resp.StatusCode == 403 {
		fmt.Fprint(w, "password is incorrect.")
		return
	}

	if resp.StatusCode != 200 {
		fmt.Fprint(w, "something went wrong")
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	type Info struct {
		ID    int    `json:"id"`
		Email string `json:"email"`
	}
	info := Info{}
	err = json.Unmarshal(body, &info)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%s", body)

	// set cookie
	setCookie(w, r, strconv.Itoa(info.ID))

	http.Redirect(w, r, "/profile", http.StatusFound)

}

func setCookie(w http.ResponseWriter, r *http.Request, value string) {
	encoded, err := s.Encode("auth", value)
	if err != nil {
		log.Fatal(err)
	}

	cookie := &http.Cookie{
		Name:     "auth",
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
	}

	http.SetCookie(w, cookie)
}

func readCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		return "", err
	}
	var value string
	err = s.Decode("auth", cookie.Value, &value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:    "auth",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (a *App) profile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, private, max-age=0, must-revalidate, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", time.Unix(0, 0).Format(http.TimeFormat))
	v := r.URL.Query()
	editMode := v.Get("edit")
	id, err := readCookie(w, r)
	if err != nil {
		log.Printf("failed getting cookie: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized. Please login first."))
		return
	}
	req, err := http.NewRequest("GET", a.ApiUrl+"/profile/"+id, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/json")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	type Data struct {
		ID          int    `json:"id"`
		FullName    string `json:"fullname"`
		Address     string `json:"address"`
		Email       string `json:"email"`
		PhoneNumber string `json:"phoneNumber"`
		EditMode    string `json:"editMode"`
		GoogleAuth  int    `json:"google_auth"`
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	data := Data{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Fatal(err)
	}

	data.EditMode = editMode

	t, err := template.ParseFiles("profile.html")
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Fatal(err)
	}

}
func (a *App) saveRegister(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	req, err := http.NewRequest("POST", a.ApiUrl+"/register", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read response
	if resp.StatusCode != 200 {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("something went wrong"))
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", body)

	type User struct {
		ID int `json:"id"`
	}

	user := User{}
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}

	setCookie(w, r, strconv.Itoa(user.ID))
	http.Redirect(w, r, "/profile?edit=true", http.StatusFound)

}

func (a *App) saveProfile(w http.ResponseWriter, r *http.Request) {
	id, err := readCookie(w, r)
	if err != nil {
		log.Printf("failed getting cookie: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized. Please login first."))
		return
	}

	googleAuth := r.FormValue("google_auth")
	email := r.FormValue("email")
	fullname := r.FormValue("fullname")
	address := r.FormValue("address")
	phonenumber := r.FormValue("phonenumber")

	form := url.Values{}
	form.Set("id", id)
	form.Set("google_auth", googleAuth)
	form.Set("email", email)
	form.Set("fullname", fullname)
	form.Set("address", address)
	form.Set("phonenumber", phonenumber)
	req, err := http.NewRequest("POST", a.ApiUrl+"/profile", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read response
	if resp.StatusCode != 200 {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("something went wrong"))
		return
	}

	http.Redirect(w, r, "/profile", http.StatusFound)

}

func (a *App) reset(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	token := params["token"]
	t, err := template.ParseFiles("reset.html")
	if err != nil {
		log.Fatal(err)
	}

	type Reset struct {
		Token string
	}

	data := Reset{}
	data.Token = token
	err = t.Execute(w, data)
	if err != nil {
		log.Fatal(err)
	}
}

func (a *App) saveReset(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	password := r.FormValue("password")

	form := url.Values{}
	form.Set("token", token)
	form.Set("password", password)
	req, err := http.NewRequest("POST", a.ApiUrl+"/reset", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read response
	if resp.StatusCode != 200 {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("something went wrong"))
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)

}
