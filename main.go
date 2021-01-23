package main

import (
	"os"
	"log"
)

func main() {
	app := App{}
	app.Init(
		os.Getenv("APP_DBUSER"),
		os.Getenv("APP_DBPASS"),
		os.Getenv("APP_DBNAME"),
		os.Getenv("APP_DBHOST"))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Listening on :80...")
	app.Run(":80")

}


