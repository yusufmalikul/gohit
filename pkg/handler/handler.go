// Package handler
// All handler goes here
package handler

import (
	"github.com/gorilla/mux"
	"gohit/pkg/api"
	"gohit/pkg/database"
)

func InitRoutes(router *mux.Router, db database.BaseHandler) {
	base := api.SetDatabase(db)
	router.HandleFunc("/register", base.Register).Methods("POST")
	router.HandleFunc("/profile/{id}", base.GetProfile).Methods("GET")
	router.HandleFunc("/profile", base.SaveProfile).Methods("POST")
	router.HandleFunc("/login", base.Login).Methods("POST")
	router.HandleFunc("/forgot", base.Forgot).Methods("POST")
	router.HandleFunc("/reset", base.Reset).Methods("POST")
	router.HandleFunc("/reset/{token}", base.ResetCheck).Methods("GET")
	router.HandleFunc("/auth/google/callback", base.GoogleCallback).Methods("GET")
}
