package main

import (
//	"database/sql"
)

type User struct {
	ID int `json:"id"`
	FullName string `json:"fullname"`
	Address string `json:"address"`
	PhoneNumber string `json:"phoneNumber"`
}

