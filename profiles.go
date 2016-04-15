package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/satori/go.uuid"
)

const baseMendeleyURL = "https://api.mendeley.com"

// Profile contains the information for any Mendeley profile
type Profile struct {
	ID          uuid.UUID `json:"id"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	DisplayName string    `json:"display_name"`
}

// GetMyProfile retrieve the profile for the logged user
func GetMyProfile(authToken string) (*Profile, error) {

	apiURL := newURL(baseMendeleyURL)
	apiURL.Path = "/profiles/me"

	req, err := http.NewRequest("GET", apiURL.String(), nil)
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error when retrieving the logged profile: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		var b bytes.Buffer
		b.ReadFrom(res.Body)

		log.Printf("GET /profiles/me returned %v %v: %v", res.StatusCode, res.Status, b.String)
		return nil, fmt.Errorf("Unexpected status code %v from GET /profiles/me", res.StatusCode)
	}

	profile := &Profile{}
	if err := json.NewDecoder(res.Body).Decode(profile); err != nil {
		return nil, fmt.Errorf("Error parsing the profile: %v", err)
	}

	return profile, nil
}

func newURL(rawURL string) *url.URL {
	URL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		panic(err)
	}

	return URL
}
