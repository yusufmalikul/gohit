package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

const ClientId = "693851654174-2rpkkd7gp95brtf90cofsg4mcj4mkaiq.apps.googleusercontent.com"
const ClientSecret = "0tKreN72PjKDuZmMM7E3UdX5"
const RedirectUri = "http://143.110.157.194.xip.io/auth/google/callback"
const ResponseType = "code"
const SCOPE = "profile https://www.googleapis.com/auth/user.addresses.read https://www.googleapis.com/auth/user.emails.read https://www.googleapis.com/auth/user.phonenumbers.read"

func googleLogin(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=%s&&scope=%s",
		ClientId,
		RedirectUri,
		ResponseType,
		SCOPE,
	),
		http.StatusFound)
}

func dbConn() (db *sql.DB) {
	dbDriver := "mysql"
	dbUser := "root"
	dbPass := "$@#12345678"
	dbName := "gogoauth"
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		log.Fatal(err)
	}

	return db

}

func googleCallback(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	code := v.Get("code")
	log.Printf("code: %s", code)
	tokenUrl := "https://oauth2.googleapis.com/token"
	log.Printf("accessing token")

	form := url.Values{}
	form.Set("client_id", ClientId)
	form.Set("client_secret", ClientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", RedirectUri)
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
	profileUrl := "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses,addresses,phoneNumbers"
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
	type Name struct {
		DisplayName string `json:"displayName"`
	}

	type Email struct {
		Value string `json:"value"`
	}

	type Addresses struct {
		StreetAddress string `json:"streetAddress"`
	}

	type PhoneNumbers struct {
		Value string `json:"value"`
	}

	type UserInfo struct {
		Name         []Name         `json:"names"`
		Email        []Email        `json:"emailAddresses"`
		Addresses    []Addresses    `json:"addresses"`
		PhoneNumbers []PhoneNumbers `json:"phoneNumbers"`
	}

	type User struct {
		Name string
		Email string
		Address string
		PhoneNumber string
	}

	var userInfo UserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		log.Fatal(err)
	}

	var user User
	user.Name = userInfo.Name[0].DisplayName
	user.Email = userInfo.Email[0].Value
	if userInfo.Addresses != nil {
		user.Address = userInfo.Addresses[0].StreetAddress
	} else {
		user.Address = ""
	}
	if userInfo.PhoneNumbers != nil {
		user.PhoneNumber = userInfo.PhoneNumbers[0].Value
	} else {
		user.PhoneNumber = ""
	}


	log.Printf("%s", user)
	log.Printf("name: %s", user.Name)
	log.Printf("email: %s", user.Email)
	log.Printf("address: %s", user.Address)
	log.Printf("phoneNumber: %s", user.PhoneNumber)

	// set cookie
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := &http.Cookie{
		Name:    "email",
		Value:   user.Email,
		Path:    "/",
		Expires: expiration,
	}

	http.SetCookie(w, cookie)


	// save to db
	db := dbConn()
	defer db.Close()
	query, err := db.Prepare("INSERT INTO user(email, fullname, address, phonenumber) VALUES (?,?,?,?)")
	if err != nil {
		log.Fatal(err)
	}
	query.Exec(user.Email, user.Name, user.Address, user.PhoneNumber)

	log.Printf("inserting data...")

	_, err = w.Write([]byte(cookie.Value))
	if err != nil {
		log.Fatal(err)
	}
}
