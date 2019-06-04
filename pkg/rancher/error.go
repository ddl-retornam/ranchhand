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

func newAuthError(resp *http.Response) *authError {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return &authError{Body: string(body)}
}

// IsUnauthorized returns a boolean indicating whether the error is known to report that an API request is unauthorized.
// A null error value will result in false being returned.
func IsUnauthorized(err error) bool {
	_, ok := err.(*authError)
	return ok
}
