package rancher

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

var HttpClient = http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

const (
	PingPath           = "/ping"
	LoginPath          = "/v3-public/localProviders/local?action=login"
	ChangePasswordPath = "/v3/users?action=changepassword"
)

type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type loginResponse struct {
	Token string
}

func Ping(host string) error {
	ping, err := buildURL(host, PingPath)
	if err != nil {
		return err
	}
	resp, err := HttpClient.Get(ping)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return responseErr(resp)
	}
	return nil
}

func Login(host string, creds *LoginCredentials) (token string, err error) {
	login, err := buildURL(host, LoginPath)
	if err != nil {
		return
	}
	body, err := json.Marshal(creds)
	if err != nil {
		return
	}
	resp, err := HttpClient.Post(login, "application/json", bytes.NewBuffer(body))
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

func ChangePassword(host, token string, input *ChangePasswordInput) error {
	cp, err := url.Parse(fmt.Sprintf("https://%s/v3/users?action=changepassword", host))
	if err != nil {
		return err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", cp.String(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	bearer := "Bearer " + token
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := HttpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "rancher password change request failed")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return errors.Errorf("rancher password change returned unexpected status (%d): %v", resp.StatusCode, string(body))
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
