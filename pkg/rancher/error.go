package rancher

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

type authError struct {
	Body string
}

func (e *authError) Error() string {
	return fmt.Sprintf("rancher login unauthorized: %s", e.Body)
}

func IsUnauthorized(err error) bool {
	_, ok := err.(*authError)
	return ok
}

func newAuthError(resp *http.Response) *authError {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return &authError{Body: string(body)}
}
