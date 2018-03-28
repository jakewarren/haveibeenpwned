package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	gock "gopkg.in/h2non/gock.v1"
)

func TestLookupEmailBreaches(t *testing.T) {
	defer gock.Off() // Flush pending mocks after test execution

	//test a successful call
	gock.New("https://haveibeenpwned.com").
		Reply(200).JSON(`[{
	"Title": "000webhost",
	"Name": "000webhost",
	"Domain": "000webhost.com",
	"BreachDate": "2015-03-01",
	"AddedDate": "2015-10-26T23:35:45Z",
	"ModifiedDate": "2015-10-26T23:35:45Z",
	"PwnCount": 13545468,
	"Description": "In approximately March 2015, the free web hosting provider <a href=\"http://www.troyhunt.com/2015/10/breaches-traders-plain-text-passwords.html\" target=\"_blank\" rel=\"noopener\">000webhost suffered a major data breach</a> that exposed over 13 million customer records. The data was sold and traded before 000webhost was alerted in October. The breach included names, email addresses and plain text passwords.",
	"DataClasses": ["Email addresses", "IP addresses", "Names", "Passwords"],
	"IsVerified": true,
	"IsFabricated": false,
	"IsSensitive": false,
	"IsActive": true,
	"IsRetired": false,
	"IsSpamList": false,
	"LogoType": "png"
}]`)

	breaches, err := LookupEmailBreaches("test@example.com")

	//err should be nil
	assert.Nil(t, err)

	//test a few values to make sure the JSON was decoded correctly
	gotBreach := breaches[0]
	assert.Equal(t, "000webhost", gotBreach.Title, "decoded breach title not equal")
	assert.Equal(t, int64(13545468), gotBreach.PwnCount, "decoded breach pwn count not equal")

	//test a 400 response code
	gock.New("https://haveibeenpwned.com").
		Reply(400)
	_, err = LookupEmailBreaches("test@example.com")
	if assert.NotNil(t, err, "testing 400 status code") {
		assert.Equal(t, "bad request - the provided email address is not acceptable", err.Error(), "testing 400 status code")
	}

	//test a 404 response code
	gock.New("https://haveibeenpwned.com").
		Reply(404)
	_, err = LookupEmailBreaches("test@example.com")
	if assert.NotNil(t, err, "testing 404 status code") {
		assert.Equal(t, "not found - the account could not be found at haveibeenpwned.com", err.Error(), "testing 404 status code")
	}

	//test a 429 response code
	gock.New("https://haveibeenpwned.com").
		Reply(429)
	_, err = LookupEmailBreaches("test@example.com")
	if assert.NotNil(t, err, "testing 429 status code") {
		assert.Equal(t, "rate limit exceeded", err.Error(), "testing 429 status code")
	}

	//test invalid json
	gock.New("https://haveibeenpwned.com").
		Reply(200).
		JSON("{this is broken JSON! ")

	_, jsonErr := LookupEmailBreaches("test@example.com")
	if assert.NotNil(t, jsonErr, "invalid json should produce error") {
		assert.Equal(t, "invalid character 't' looking for beginning of object key string", jsonErr.Error(), "did not receive expected JSON error")
	}

}

func TestLookupEmailPastes(t *testing.T) {
	defer gock.Off() // Flush pending mocks after test execution

	//test a successful call
	gock.New("https://haveibeenpwned.com").
		Reply(200).JSON(`[
{
"Source":"Pastebin",
"Id":"8Q0BvKD8",
"Title":"syslog",
"Date":"2014-03-04T19:14:54Z",
"EmailCount":139
},
{
"Source":"Pastie",
"Id":"7152479",
"Date":"2013-03-28T16:51:10Z",
"EmailCount":30
}
]`)

	pastes, err := LookupEmailPastes("test@example.com")

	//err should be nil
	assert.Nil(t, err)

	//test a few values to make sure the JSON was decoded correctly
	gotPaste := pastes[0]
	assert.Equal(t, "Pastebin", gotPaste.Source, "decoded paste source not equal")
	assert.Equal(t, "8Q0BvKD8", gotPaste.ID, "decoded paste id not equal")
	assert.Equal(t, "syslog", gotPaste.Title, "decoded paste title not equal")

	//test a 400 response code
	gock.New("https://haveibeenpwned.com").
		Reply(400)
	_, err = LookupEmailPastes("test@example.com")
	if assert.NotNil(t, err, "testing 400 status code") {
		assert.Equal(t, "bad request - the provided email address is not acceptable", err.Error(), "testing 400 status code")
	}

	//test a 404 response code
	gock.New("https://haveibeenpwned.com").
		Reply(404)
	_, err = LookupEmailPastes("test@example.com")
	if assert.NotNil(t, err, "testing 404 status code") {
		assert.Equal(t, "not found - the account could not be found at haveibeenpwned.com", err.Error(), "testing 404 status code")
	}

	//test a 429 response code
	gock.New("https://haveibeenpwned.com").
		Reply(429)
	_, err = LookupEmailPastes("test@example.com")
	if assert.NotNil(t, err, "testing 429 status code") {
		assert.Equal(t, "rate limit exceeded", err.Error(), "testing 429 status code")
	}

	//test invalid json
	gock.New("https://haveibeenpwned.com").
		Reply(200).
		JSON("{this is broken JSON! ")

	_, jsonErr := LookupEmailPastes("test@example.com")
	if assert.NotNil(t, jsonErr, "invalid json should produce error") {
		assert.Equal(t, "invalid character 't' looking for beginning of object key string", jsonErr.Error(), "did not receive expected JSON error")
	}
}
