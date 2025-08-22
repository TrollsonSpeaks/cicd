package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// TEST CASE 1 -
	t.Run("returns API key when valid auth header is provided", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret-key-123")

		apiKey err := GetAPIKey(headers)

		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}

		if apiKey != "my-secret-key-123" {
			t.Errorf("Expected 'my-secret-key-123', but got: %s", apiKey)
		}
	})

	// TEST CASE 2 -
	t.Run("returns error when no authorization header is included", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)

		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, but got: %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, but got: %s", apiKey)
		}
	})

	// TEST CASE 3 -
	t.Run("returns error when authorization header is malformed - missing ApiKey", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer my-secret-key-123")

		apiKey, err := GetAPIKey (headers)

		if err == nil {
			t.Error("Expected an error, but got none")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header' but got: %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, but got: %s", apiKey)
		}
	})

	// TEST CASE 4 -
	t.Run("returns error when authorization header has no API key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		apiKey, err := GetAPIKey(headers)

		if err == nil {
			t.Error("Expected an error, but got none")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', but got: %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, but got: %s", apiKey)
		}
	})
}
