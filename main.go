package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/mux"
)

// Flags
var clientID = flag.String("clientId", "", "The client_id registered on dev.mendeley.com")
var clientSecret = flag.String("clientSecret", "", "The client_secret registered on dev.mendeley.com")
var redirectURI = flag.String("redirectUri", "", "The client_secret registered on dev.mendeley.com")

// Page templates
var templates *template.Template

func init() {
	templates = template.Must(template.ParseFiles(
		"templates/home.html",
		"templates/commons.html",
		"templates/navbar.html",
	))

	log.Println("Templates parse successful", templates.DefinedTemplates())
}

func main() {
	log.Println("Starting up...")
	flag.Parse()
	validateArgs()

	r := mux.NewRouter()

	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))

	log.Println("Started with PID", os.Getpid())

	log.Fatal(http.ListenAndServe(":8080", r))
}

func validateArgs() {
	if *clientID == "" {
		log.Fatalln("--clientId must be specified")
	}
	if *clientSecret == "" {
		log.Fatalln("--clientSecret must be specified")
	}
	if *redirectURI == "" {
		log.Fatalln("--redirectUri must be specified")
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET: %v", r.URL)

	session, err := retrieveSession(w, r)
	if err == errSessionNotPresent {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	delete(sessionMap, session.id)
	http.Redirect(w, r, "/", http.StatusFound)
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET: %v", r.URL)
	session, err := retrieveOrCreateSession(w, r)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, ok := session.properties["state"]; ok {
		// redirect from mendeley login
		redeemAuthCode(w, r, session)
	} else {
		// redirect to mendeley login
		state := redirectToMendeleyLogin(w, r)
		session.properties["state"] = state
	}

	return
}

func redeemAuthCode(w http.ResponseWriter, r *http.Request, session *Session) {
	r.ParseForm()
	state := r.FormValue("state")
	if session.properties["state"] != state {
		log.Printf("Auth code received, but state doesn't match %v != %v", (*session).properties["state"], state)
		delete(sessionMap, session.id)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	code := r.FormValue("code")
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

	session.accessToken = authBody.AccessToken

	http.Redirect(w, r, "/", http.StatusFound)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET: %v", r.URL)

	s, err := retrieveOrCreateSession(w, r)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if s.IsLogged() {
		me, err := GetMyProfile(s.accessToken)
		if err != nil {
			log.Println("Error retrieving the logged profile:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		s.Me = me
	}

	writeHTML(w, "home.html", struct {
		Me *Profile
	}{s.Me})
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

func writeHTML(w http.ResponseWriter, templateName string, data interface{}) {
	err := templates.ExecuteTemplate(w, templateName, data)
	if err != nil {
		log.Println("Template can't be executed:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
