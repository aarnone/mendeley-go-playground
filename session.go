package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/satori/go.uuid"
)

// Session (in-memory)
var sessionMap = map[uuid.UUID]*Session{}

func retrieveOrCreateSession(w http.ResponseWriter, r *http.Request) (*Session, error) {

	sessCookie, err := r.Cookie("_session")
	if err == http.ErrNoCookie {
		// new session
		ses := createSession(w)
		log.Print("New session", ses.id)

		return ses, nil
	} else if err != nil {
		return nil, fmt.Errorf("Failed to establish session: %v", err)
	}

	sessCookieVal, err := url.QueryUnescape(sessCookie.Value)
	if err != nil {
		return nil, fmt.Errorf("Failed to establish session: %v", err)
	}

	sessionID, err := uuid.FromString(sessCookieVal)
	if err != nil {
		return nil, fmt.Errorf("Failed to establish session: %v", err)
	}

	ses, ok := sessionMap[sessionID]
	if !ok {
		ses := createSession(w)
		log.Println("Session doesn't exist, create a new one", ses.id)

		return ses, nil
	}

	return ses, nil
}

func createSession(w http.ResponseWriter) *Session {
	newSession := &Session{uuid.NewV4(), "", map[string]interface{}{}}
	sessionMap[newSession.id] = newSession

	sessionCookie := http.Cookie{
		Name:     "_session",
		Value:    url.QueryEscape(newSession.id.String()),
		HttpOnly: true,
	}
	http.SetCookie(w, &sessionCookie)

	log.Printf("NewSession: %v\n", newSession.id)

	return newSession
}

// Session represent web session
type Session struct {
	id          uuid.UUID
	accessToken string
	properties  map[string]interface{}
}

// IsLogged if the Session is valid and logged in
func (s *Session) IsLogged() bool {
	return s != nil && s.accessToken != ""
}

func (s *Session) String() string {
	return fmt.Sprintf("{ id: %v, state: %v }", s.id, s.properties["state"])
}
