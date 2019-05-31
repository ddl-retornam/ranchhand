package rancher

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPing(t *testing.T) {
	testcases := []struct {
		name      string
		handler   http.Handler
		expectErr bool
	}{
		{
			"success",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/ping", r.URL.Path)
			}),
			false,
		},
		{
			"server_error",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}),
			true,
		},
		{
			"bad_status",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusMovedPermanently)
			}),
			true,
		},
	}

	ts, host := newTestServer()
	defer ts.Close()

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ts.Config.Handler = tc.handler

			err := Ping(host)
			assert.Equal(t, tc.expectErr, err != nil, "err: %v", err)
		})
	}
}

func TestLogin(t *testing.T) {
	ts, host := newTestServer()
	defer ts.Close()

	validResponse := []byte(`{"token": "black"}`)
	creds := LoginCredentials{
		Username: "asl",
		Password: "plz",
	}

	t.Run("success", func(t *testing.T) {
		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := ioutil.ReadAll(r.Body)
			assert.JSONEq(t, `{"username": "asl", "password": "plz"}`, string(body))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "/v3-public/localProviders/local", r.URL.Path)
			assert.Equal(t, "action=login", r.URL.RawQuery)

			w.WriteHeader(http.StatusCreated)
			w.Write(validResponse)
		})

		token, err := Login(host, &creds)
		assert.Equal(t, "black", token)
		assert.NoError(t, err)
	})

	t.Run("server_error", func(t *testing.T) {
		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write(validResponse)
		})

		_, err := Login(host, &creds)
		assert.Error(t, err)
	})

	t.Run("unauthorized", func(t *testing.T) {
		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(validResponse)
		})

		_, err := Login(host, &creds)
		assert.IsType(t, &authError{}, err)
	})

	t.Run("bad_status", func(t *testing.T) {
		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(validResponse))
		})

		_, err := Login(host, &creds)
		assert.Error(t, err)
	})

	t.Run("malformed_response", func(t *testing.T) {
		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`a-b-c-easy-as-1-2-3`))
		})

		_, err := Login(host, &creds)
		assert.Error(t, err)
	})
}

func TestChangePassword(t *testing.T) {
	t.Skip("write a test")
}

func newTestServer() (*httptest.Server, string) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	u, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}

	return ts, u.Host
}
