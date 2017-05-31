package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	breachAPIURL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s?includeUnverified=true"
	pasteAPIURL  = "https://haveibeenpwned.com/api/v2/pasteaccount/%s"
)

// Breaches contains the details for each breach
type Breaches struct {
	AddedDate    string   `json:"AddedDate"`
	BreachDate   string   `json:"BreachDate"`
	DataClasses  []string `json:"DataClasses"`
	Description  string   `json:"Description"`
	Domain       string   `json:"Domain"`
	IsActive     bool     `json:"IsActive"`
	IsFabricated bool     `json:"IsFabricated"`
	IsRetired    bool     `json:"IsRetired"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsSpamList   bool     `json:"IsSpamList"`
	IsVerified   bool     `json:"IsVerified"`
	LogoType     string   `json:"LogoType"`
	Name         string   `json:"Name"`
	PwnCount     int64    `json:"PwnCount"`
	Title        string   `json:"Title"`
}

// Pastes contains the details for each past
type Pastes struct {
	Date       string `json:"Date"`
	EmailCount int64  `json:"EmailCount"`
	ID         string `json:"Id"`
	Source     string `json:"Source"`
	Title      string `json:"Title"`
}

// LookupEmailBreaches returns the breach information for a given email address from HIBP.
func LookupEmailBreaches(email string) (breaches []Breaches, err error) {
	//lookup the breach data for the email
	endpoint := fmt.Sprintf(breachAPIURL, url.QueryEscape(email))
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	//add user agent to respect API spec
	req.Header.Set("User-Agent", "haveibeenpwned")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	//check for errors from haveibeenpwned
	switch resp.StatusCode {
	case 400:
		return nil, errors.New("bad request - the provided email address is not acceptable")
	case 404:
		return nil, errors.New("not found - the account could not be found at haveibeenpwned.com")
	case 429:
		return nil, errors.New("rate limit exceeded")
	}

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(&breaches); err != nil {
		return nil, err
	}

	return breaches, nil
}

// LookupEmailPastes returns the pastes from haveibeenpwned for a given
func LookupEmailPastes(email string) (pastes []Pastes, err error) {
	//lookup the paste data for the email
	endpoint := fmt.Sprintf(pasteAPIURL, url.QueryEscape(email))
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	//add user agent to respect API spec
	req.Header.Set("User-Agent", "haveibeenpwned")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	//check for errors from haveibeenpwned
	switch resp.StatusCode {
	case 400:
		return nil, errors.New("bad request - the provided email address is not acceptable")
	case 404:
		return nil, errors.New("not found - the account could not be found at haveibeenpwned.com")
	case 429:
		return nil, errors.New("rate limit exceeded")
	}

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(&pastes); err != nil {
		return nil, err
	}

	return pastes, nil
}
