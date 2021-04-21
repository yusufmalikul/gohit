/*
Contains commonly used functions
*/

package common

import (
	"encoding/json"
	"net/http"
	"net/smtp"
	"os"
)

func RespondWithError(w http.ResponseWriter, code int, message string) {
	RespondWithJSON(w, code, map[string]interface{}{"error": true, "message": message})
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}

func SendEmail(to, subject, msg string) error {
	from := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	body := "From: " + from + "\n" + "To: " + to + "\n" + subject + "\n\n" + msg

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(body))
	return err
}
