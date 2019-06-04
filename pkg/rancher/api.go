package rancher

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

// HTTPClient is the default client used to communicate with the Rancher API. By default, it has TLS verification
// disabled. You can modify the variable with you own client to modify the behavior of the underlying http calls.
var HTTPClient = http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

const (
	pingPath           = "/ping"
	loginPath          = "/v3-public/localProviders/local?action=login"
	changePasswordPath = "/v3/users?action=changepassword"
)

// LoginInput defines the credentials required to authenticate with the Rancher API.
type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ChangePasswordInput defines the data required to change a user's password.
type ChangePasswordInput struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// loginResponse maps a portion of the JSON response from a successful login request. Add more fields to the struct if
// you require additional data from the body of the response.
type loginResponse struct {
	Token string
}

// Ping is used to verify that a Rancher instance is running and healthy. Any response status other than 200 will result
// in an error.
func Ping(host string) error {
	pingURL, err := buildURL(host, pingPath)
	if err != nil {
		return err
	}
	resp, err := HTTPClient.Get(pingURL)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return responseErr(resp)
	}
	return nil
}

// Login will use the provided credentials to request an API token from Rancher. This API token is required to make any
// request that requires authentication.
func Login(host string, creds *LoginInput) (token string, err error) {
	loginURL, err := buildURL(host, loginPath)
	if err != nil {
		return
	}
	body, err := json.Marshal(creds)
	if err != nil {
		return
	}
	resp, err := HTTPClient.Post(loginURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		err = newAuthError(resp)
		return
	case resp.StatusCode != http.StatusCreated:
		err = responseErr(resp)
		return
	}

	response := new(loginResponse)
	if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
		return "", errors.Wrap(err, "malformed rancher response")
	}
	return response.Token, nil
}

// ChangePassword will update the password of the user associated with the provided API token. Any response status other
// than 200 will result in an error.
func ChangePassword(host, token string, input *ChangePasswordInput) error {
	cpURL, err := buildURL(host, changePasswordPath)
	if err != nil {
		return err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", cpURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	bearer := "Bearer " + token
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return responseErr(resp)
	}
	return nil
}

func buildURL(host, path string) (string, error) {
	u, err := url.ParseRequestURI("https://" + host + path)
	if err != nil {
		return "", errors.Wrap(err, "cannot build rancher url")
	}
	return u.String(), nil
}

func responseErr(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return errors.Errorf("rancher request failed [status: %d] [body: %v]", resp.StatusCode, string(body))
}
