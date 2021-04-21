// Package api
// API call function defined here
package api

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"gohit/pkg/common"
	"gohit/pkg/database"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type BaseHandler struct {
	db database.BaseHandler
}

func SetDatabase(db database.BaseHandler) *BaseHandler {
	return &BaseHandler{db: db}
}

func (h BaseHandler) Register(w http.ResponseWriter, r *http.Request) {
	log.Println("POST /Register")
	email := r.FormValue("email")
	password := r.FormValue("password")
	if email == "" || password == "" {
		log.Println("empty email/password")
		common.RespondWithError(w, http.StatusBadRequest, "email/password can't be empty")
		return
	}
	log.Printf("email: %s password: %s", email, password)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}
	id, err := h.db.Register(email, passwordHash)
	if err != nil {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"id": id})
}
func (h BaseHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]
	log.Println("GetProfile:", id)
	var userId, googleAuth int
	var fullname, email, address, phonenumber string
	err := h.db.GetProfile(&userId, &googleAuth, &id, &fullname, &email, &address, &phonenumber)
	if err != nil {
		if err == sql.ErrNoRows {
			common.RespondWithError(w, http.StatusNotFound, "not found")
			return
		} else {
			log.Println(err)
			common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
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

	common.RespondWithJSON(w, http.StatusOK, data)
}

func (h BaseHandler) Login(w http.ResponseWriter, r *http.Request) {
	log.Println("POST /Login")
	email := r.FormValue("email")
	password := r.FormValue("password")
	var userId int
	var passwordHash string
	err := h.db.GetLoginDetail(&userId, &passwordHash, email)
	if err != nil {
		if err == sql.ErrNoRows {
			common.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		} else {
			log.Println(err)
			common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
			return
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		common.RespondWithError(w, http.StatusForbidden, "password incorrect")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"id": userId, "email": email})
}

const ClientId = "693851654174-2rpkkd7gp95brtf90cofsg4mcj4mkaiq.apps.googleusercontent.com"

func (h BaseHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	code := v.Get("code")
	redirectUri := v.Get("redirect_uri")

	log.Printf("code: %s", code)
	tokenUrl := "https://oauth2.googleapis.com/token"
	log.Printf("accessing token")

	form := url.Values{}
	form.Set("client_id", ClientId)
	form.Set("client_secret", os.Getenv("CLIENT_SECRET"))
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectUri)
	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(form.Encode()))
	if err != nil {
		log.Print(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		log.Print(err)
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
			log.Print(err)
		}
		log.Printf("%s", bodyBytes)
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Print(err)
	}
	log.Printf("access_token: %s", data.AccessToken)
	log.Printf("scope: %s", data.Scope)

	log.Printf("getting userinfo")
	profileUrl := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err = http.NewRequest("GET", profileUrl, nil)
	if err != nil {
		log.Print(err)
	}
	req.Header.Add("Authorization", "Bearer "+data.AccessToken)
	resp, err = hc.Do(req)
	if err != nil {
		log.Print(err)
	}

	type UserInfo struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	var user UserInfo
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		log.Print(err)
	}

	log.Printf("%s", user)
	log.Printf("name: %s", user.Name)
	log.Printf("email: %s", user.Email)

	// check if user exists
	currentId, err := h.db.GetIdByEmail(user.Email)
	if err != nil && err != sql.ErrNoRows {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	if currentId != 0 {
		// user exists
		log.Printf("user exists")
		common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"id": currentId})
		return
	}

	// save to db
	id, err := h.db.RegisterGoogle(user.Email, user.Name)
	if err != nil && err != sql.ErrNoRows {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}
	log.Printf("inserting data...")
	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"id": id})
}

func (h BaseHandler) SaveProfile(w http.ResponseWriter, r *http.Request) {
	log.Println("saving user profile")
	id := r.FormValue("id")
	googleAuth := r.FormValue("google_auth")
	email := r.FormValue("email")
	fullname := r.FormValue("fullname")
	address := r.FormValue("address")
	phonenumber := r.FormValue("phonenumber")

	err := h.db.SaveProfile(fullname, address, phonenumber, email, id, googleAuth)
	if err != nil {
		log.Print(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "success"})

}

func (h BaseHandler) Forgot(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	to := email
	hash := fmt.Sprintf("%x", md5.Sum([]byte(time.Now().Format("20060102150405"))))

	_, err := h.db.SetResetToken(hash, email)
	if err != nil {
		log.Println("failed when setting reset token")
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	subject := "Subject: Reset Password - Gogoauth"
	msg := "Hello, Please follow this link to reset password https://gogoauth.herokuapp.com/reset/" + hash + " (will expire in 15 minutes)."

	go func() {
		_ = common.SendEmail(to, subject, msg)
	}()

	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "success"})
}

func (h BaseHandler) Reset(w http.ResponseWriter, r *http.Request) {
	log.Println("POST /reset")
	token := r.FormValue("token")
	password := r.FormValue("password")
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	err = h.db.ResetPassword(passwordHash, token)
	if err != nil {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "success"})
}

func (h BaseHandler) ResetCheck(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	token := params["token"]

	isValid, err := h.db.CheckResetToken(token)
	if err != nil {
		log.Println(err)
		common.RespondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	if !isValid {
		common.RespondWithError(w, http.StatusNotFound, "reset token expired")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "valid"})
}
