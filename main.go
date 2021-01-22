package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
)

type PageVariables struct {
	Date    string
	Time    string
	Success bool
}

func main() {
	http.HandleFunc("/", Home)
	fmt.Println("listening on 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
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


