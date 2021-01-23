package main

import (
	"./handler"
	"fmt"
	"log"
	"net/http"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	server := &http.Server{
		Addr: fmt.Sprintf(":80"),
		Handler: handler.New(),
	}
	log.Printf("Starting HTTP Server. Listening at %v", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}


