package handler

import (
	"html/template"
	"log"
	"net/http"
	"time"
)

func New() http.Handler {
	mux := http.NewServeMux()
	// Root
	mux.HandleFunc("/", Home)

	// OauthGoogle
	mux.HandleFunc("/auth/google/login", googleLogin)
	mux.HandleFunc("/auth/google/callback", googleCallback)

	return mux
}

type PageVariables struct {
	Date    string
	Time    string
	Success bool
}

func Home(w http.ResponseWriter, r *http.Request)  {
	now := time.Now()
	HomePageVars := PageVariables{
		Date: now.Format("02-01-2006"),
		Time: now.Format("15:04:05"),
		Success: false,
	}

	t, err := template.ParseFiles("home.html")
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, HomePageVars)
	if err != nil {
		log.Fatal(err)
	}
}