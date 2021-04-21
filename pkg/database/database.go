// Package database
// Used for database stuff
package database

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

type BaseHandler struct {
	db *sql.DB
}

func New(user, pass, dbname, dbhost string) BaseHandler {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", user, pass, dbhost, dbname)
	var err error
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	return BaseHandler{db}
}

const register = `INSERT INTO users (email, password) VALUES (?,?)`
const registerGoogle = `INSERT INTO users (email, fullname, google_auth) VALUES (?,?,?)`
const getIdByEmail = `SELECT id FROM users WHERE email = ?`
const saveProfilewoEmail = "UPDATE users SET fullname = ?, address = ?, phonenumber = ? WHERE id = ?"
const saveProfilewithEmail = "UPDATE users SET fullname = ?, address = ?, phonenumber = ?, email = ? WHERE id = ?"
const setToken = "UPDATE users SET reset_token = ?, reset_token_exp = (NOW() + INTERVAL 15 MINUTE) WHERE email = ?"
const resetPassword = "UPDATE users SET password = ? WHERE reset_token = ?"
const checkToken = `SELECT email FROM users WHERE reset_token = ? AND NOW() < reset_token_exp`
const loginDetail = `SELECT id, password FROM users WHERE email = ?`
const getProfile = `SELECT id, fullname, email, address, phonenumber, google_auth FROM users WHERE id = ?`

func (h *BaseHandler) Register(email string, password []byte) (int64, error) {

	query, err := h.db.Prepare(register)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	res, err := query.Exec(email, password)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		log.Println(err)
		return 0, err
	}

	return id, nil
}

func (h *BaseHandler) RegisterGoogle(email, fullname string) (int64, error) {
	// save to db
	query, err := h.db.Prepare(registerGoogle)
	if err != nil {
		return 0, err
	}
	res, err := query.Exec(email, fullname, true)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	return id, nil
}

func (h BaseHandler) GetProfile(userId, googleAuth *int, id, fullname, email, address, phonenumber *string) error {
	row := h.db.QueryRow(getProfile, id)
	err := row.Scan(userId, fullname, email, address, phonenumber, googleAuth)
	if err != nil {
		return err
	}

	return nil
}

func (h BaseHandler) GetLoginDetail(userId *int, passwordHash *string, email string) error {
	row := h.db.QueryRow(loginDetail, email)
	err := row.Scan(userId, passwordHash)
	if err != nil {
		return err
	}
	return nil
}

func (h BaseHandler) GetIdByEmail(email string) (int, error) {
	row := h.db.QueryRow(getIdByEmail, email)
	var currentId int
	err := row.Scan(&currentId)
	if err != nil {
		return 0, err
	}
	return currentId, nil
}

func (h BaseHandler) SaveProfile(fullname, address, phonenumber, email, id, googleAuth string) error {
	if googleAuth == "1" {
		query, err := h.db.Prepare(saveProfilewoEmail)
		if err != nil {
			return err
		}
		_, _ = query.Exec(fullname, address, phonenumber, id)
	} else {
		query, err := h.db.Prepare(saveProfilewithEmail)
		if err != nil {
			return err
		}
		_, _ = query.Exec(fullname, address, phonenumber, email, id)
	}

	return nil
}

func (h BaseHandler) SetResetToken(hash, email string) (sql.Result, error) {
	query, err := h.db.Prepare(setToken)
	if err != nil {
		return nil, err
	}
	res, err := query.Exec(hash, email)
	return res, err
}

func (h BaseHandler) ResetPassword(passwordHash []byte, token string) error {
	query, err := h.db.Prepare(resetPassword)
	if err != nil {
		return err
	}
	_, err = query.Exec(passwordHash, token)
	if err != nil {
		return err
	}

	return nil
}

func (h BaseHandler) CheckResetToken(token string) (bool, error) {
	row := h.db.QueryRow(checkToken, token)
	var email string
	err := row.Scan(&email)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	if err == sql.ErrNoRows {
		return false, nil
	}

	return true, nil
}
