package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
)

// Flags
var clientID = flag.String("clientId", "", "The client_id registered on dev.mendeley.com")
var clientSecret = flag.String("clientSecret", "", "The client_secret registered on dev.mendeley.com")
var redirectURI = flag.String("redirectUri", "", "The client_secret registered on dev.mendeley.com")

// Session (in-memory)
var sessionMap = map[uuid.UUID]*session{}

func main() {
	log.Println("Starting up...")
	flag.Parse()

	if *clientID == "" {
		log.Fatalln("--clientId must be specified")
	}
	if *clientSecret == "" {
		log.Fatalln("--clientSecret must be specified")
	}
	if *redirectURI == "" {
		log.Fatalln("--redirectUri must be specified")
	}

	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginCallbackHandler)

	log.Fatal(http.ListenAndServe(":8080", r))

	log.Println("Shutting down...")
}

func loginCallbackHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("GET: %v", req.URL)

	sessCookie, err := req.Cookie("_session")
	if err != nil {
		// no session cookie
		log.Print("Auth code received, but no session found")
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	sessCookieVal, _ := url.QueryUnescape(sessCookie.Value)
	sessionID, err := uuid.FromString(sessCookieVal)
	if err != nil {
		// session cookie not valid
		log.Print("Auth code received, but session cookie not valid")
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	s, ok := sessionMap[sessionID]
	if !ok {
		// session not found
		log.Print("Auth code received, but session not found")
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	log.Print("Session found: ", s)

	req.ParseForm()
	state := req.FormValue("state")
	if s.properties["state"] != state {
		log.Printf("Auth code received, but state doesn't match %v != %v", (*s).properties["state"], state)
		delete(sessionMap, s.id)
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	code := req.FormValue("code")
	log.Printf("Code received %v. Auth flow to be completed", code)

	postData := url.Values{}
	postData.Set("grant_type", "authorization_code")
	postData.Set("code", code)
	postData.Set("redirect_uri", *redirectURI)

	authRequest, err := http.NewRequest("POST", "https://api.mendeley.com/oauth/token", strings.NewReader(postData.Encode()))
	if err != nil {
		panic(fmt.Errorf("Impossibile to build the auth request: %v", err))
	}
	authRequest.SetBasicAuth(*clientID, *clientSecret)
	authRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	authResponse, err := http.DefaultClient.Do(authRequest)
	if err != nil {
		panic(fmt.Errorf("Impossibile to execute the auth request: %v", err))
	}
	defer authResponse.Body.Close()

	if authResponse.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(authResponse.Body)
		panic(fmt.Errorf("Impossibile to execute the auth request: %v: %v", authResponse.StatusCode, string(b)))
	}

	var authBody struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}

	json.NewDecoder(authResponse.Body).Decode(&authBody)

	s.accessToken = authBody.AccessToken

	http.Redirect(w, req, "/", http.StatusFound)
}

func homeHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("GET: %v", req.URL)

	sessCookie, err := req.Cookie("_session")
	if err != nil {
		// initiate login
		log.Print("Not logged request, redirect to Mendeley login")
		beginAuthorizationCodeFlow(w, req)
		return
	}

	sessCookieVal, _ := url.QueryUnescape(sessCookie.Value)
	sessionID, err := uuid.FromString(sessCookieVal)
	if err != nil {
		log.Print("Invalid session id, redirect to Mendeley login")
		beginAuthorizationCodeFlow(w, req)
		return
	}

	s, ok := sessionMap[sessionID]
	if !ok {
		log.Print("Session doesn't exist, redirect to Mendeley login")
		beginAuthorizationCodeFlow(w, req)
		return
	}

	if s.accessToken == "" {
		log.Print("Auth flow not completed, redirect to Mendeley login")
		beginAuthorizationCodeFlow(w, req)
		return
	}

	fmt.Fprint(w, "Hello World")
	log.Print("Successfully logged with accessToken: ", s.accessToken)
}

func beginAuthorizationCodeFlow(w http.ResponseWriter, req *http.Request) {
	userSession := createSession(w)
	state := redirectToMendeleyLogin(w, req)

	userSession.properties["state"] = state
}

func redirectToMendeleyLogin(w http.ResponseWriter, req *http.Request) (state string) {
	state = fmt.Sprint(rand.Float64())

	queryParams := url.Values{}
	queryParams.Set("client_id", *clientID)
	queryParams.Set("redirect_uri", *redirectURI)
	queryParams.Set("response_type", "code")
	queryParams.Set("scope", "all")
	queryParams.Set("state", state)

	loginURL := &url.URL{
		Scheme:   "https",
		Host:     "api.mendeley.com",
		Path:     "/oauth/authorize",
		RawQuery: queryParams.Encode(),
	}

	http.Redirect(w, req, loginURL.String(), http.StatusFound)

	return
}

func createSession(w http.ResponseWriter) *session {
	newSession := &session{uuid.NewV4(), "", map[string]interface{}{}}
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

// Represent web session
type session struct {
	id          uuid.UUID
	accessToken string
	properties  map[string]interface{}
}

func (s *session) String() string {
	return fmt.Sprintf("{ id: %v, state: %v }", s.id, s.properties["state"])
}
