package fetch-jwk

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

type openIDConfiguration struct {
	jwksURL string `json:"jwks_uri,omitempty"`
}

// FromIssuerClaim verifies JWT token
func FromIssuerClaim(token *jwt.Token) (interface{}, error) {
	if token == nil {
		return nil, fmt.Errorf("Token cannot be null")
	}
	claims := token.Claims.(jwt.StandardClaims)
	var discoverURL string
	if strings.HasSuffix(claims.Issuer, "/") {
		discoverURL = fmt.Sprintf("%s.well-known/openid-configuration", claims.Issuer)
	} else {
		discoverURL = fmt.Sprintf("%s/.well-known/openid-configuration", claims.Issuer)
	}
	dcvURL, err := url.Parse(discoverURL)
	if err != nil {
		return nil, fmt.Errorf("Error while getting discover url from issuer claim: %v", err)
	}
	dcvURL.Scheme = "https"
	return FromDiscoverURL(token, dcvURL.String())
}

// FromDiscoverURL vvv
func FromDiscoverURL(token *jwt.Token, discoverURL string) (interface{}, error) {
	resp, err := http.Get(discoverURL)
	if err != nil {
		resErr := fmt.Errorf("Error while getting openid connect configuration: %v", err)
		return nil, resErr
	}
	decoder := json.NewDecoder(resp.Body)
	var config openIDConfiguration
	err = decoder.Decode(&config)
	if err != nil {
		resErr := fmt.Errorf("Error while getting openid connect configuration: %v", err)
		return nil, resErr
	}
	return FromJWKsURL(token, config.jwksURL)
}

// FromJWKsURL sss
func FromJWKsURL(token *jwt.Token, jwksURL string) (interface{}, error) {
	if keyID, ok := token.Header["kid"].(string); ok {

		keySet, err := jwk.FetchHTTP(jwksURL)
		if err != nil {
			return nil, fmt.Errorf("Error while fetching jwks: %v", err)
		}
		keys := keySet.LookupKeyID(keyID)
		if keys == nil || len(keys) == 0 {
			return nil, errors.New("Token key not found in jwks uri")
		}
		if len(keys) > 1 {
			return nil, errors.New("Unexpected error. More than one key found in jwks uri")
		}
		return keys[0].Materialize()
	}
	return nil, fmt.Errorf("Token doesn't have header kid")
}
