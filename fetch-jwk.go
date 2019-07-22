package jwkfetch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/robfig/cron"
)

// JWKProvider structure for jwk config
type JWKProvider struct {
	Issuer      string
	DiscoverURL string
	JWKURL      string
}

var jwkProviders []JWKProvider
var issuerCache map[string]*jwk.Set = make(map[string]*jwk.Set)
var jwksCache map[string]*jwk.Set = make(map[string]*jwk.Set)
var discoverURLsCache map[string]*jwk.Set = make(map[string]*jwk.Set)

var errKeyNotFound = fmt.Errorf("Token key not found in jwks uri")

// FromIssuerClaim extracts issuer from JWT token assuming that OpenID discover URL is <iss>+/.well-known/openid-configuration. Then fetches JWT keys from jwks_url found in configuration
func FromIssuerClaim() func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		claims := token.Claims.(jwt.MapClaims)
		issuer := claims["iss"].(string)

		return retrieveKey(token, issuer, issuerCache, getKeySetFromIssuerCache)
	}
}

// FromDiscoverURL - fetches JWT keys from jwks_url found in configuration from OpenID discover URL.
func FromDiscoverURL(discoverURL string) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return retrieveKey(token, discoverURL, discoverURLsCache, getKeySetFromDiscoverURLCache)
	}
}

// FromJWKsURL fetches JWT keys from jwks_url
func FromJWKsURL(jwksURL string) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return retrieveKey(token, jwksURL, jwksCache, getKeySetFromJWKCache)
	}
}

func retrieveKey(token *jwt.Token, cacheKey string, cache map[string]*jwk.Set, retrieveFn func(string) (*jwk.Set, error)) (interface{}, error) {
	keyID, err := getKeyID(token)
	if err != nil {
		return nil, err
	}

	keySet, err := retrieveFn(cacheKey)
	if err != nil {
		return nil, err
	}

	key, err := getKey(keySet, keyID)
	if err == errKeyNotFound {
		delete(cache, cacheKey)
		freshKeySet, err := retrieveFn(cacheKey)
		if err != nil {
			return nil, err
		}
		return getKey(freshKeySet, keyID)
	}
	return key, err
}

func getKeyID(token *jwt.Token) (string, error) {
	if keyID, ok := token.Header["kid"].(string); ok {
		return keyID, nil
	}
	return "", fmt.Errorf("Token doesn't have header kid")
}

func getKey(keySet *jwk.Set, keyID string) (interface{}, error) {
	keys := keySet.LookupKeyID(keyID)
	if keys == nil || len(keys) == 0 {
		return nil, errKeyNotFound
	}
	if len(keys) > 1 {
		return nil, errors.New("Unexpected error. More than one key found in jwks uri")
	}
	return keys[0].Materialize()
}

func getKeySet(jwksURL string) (*jwk.Set, error) {
	keySet, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("Error while fetching jwks: %v", err)
	}
	return keySet, nil
}

func getKeySetFromJWKCache(jwksURL string) (*jwk.Set, error) {
	var keySet *jwk.Set
	var ok bool
	var err error
	if keySet, ok = jwksCache[jwksURL]; !ok {
		keySet, err = getKeySet(jwksURL)
		if err != nil {
			return nil, err
		}
		jwksCache[jwksURL] = keySet
	}
	return keySet, nil
}

func getKeySetFromDiscoverURLCache(discoverURL string) (*jwk.Set, error) {
	var keySet *jwk.Set
	var ok bool
	if keySet, ok = discoverURLsCache[discoverURL]; !ok {
		jwksURL, err := getJWKsURL(discoverURL)
		if err != nil {
			return nil, err
		}

		keySet, err = getKeySetFromJWKCache(jwksURL)
		if err != nil {
			return nil, err
		}
		discoverURLsCache[discoverURL] = keySet
	}
	return keySet, nil
}

func getKeySetFromIssuerCache(issuer string) (*jwk.Set, error) {
	var keySet *jwk.Set
	var ok bool
	var err error
	if keySet, ok = issuerCache[issuer]; !ok {
		keySet, err = getKeySetFromProvidedConfig(issuer)
		if err != nil {
			return nil, err
		}

		if keySet == nil {
			discoverURL, err := getDiscoverURL(issuer)
			if err != nil {
				return nil, err
			}
			keySet, err = getKeySetFromDiscoverURLCache(discoverURL)
			if err != nil {
				return nil, err
			}
			issuerCache[issuer] = keySet
		}
	}
	return keySet, nil

}

func getKeySetFromProvidedConfig(issuer string) (*jwk.Set, error) {
	if jwkProviders != nil {
		for _, jwkProvider := range jwkProviders {
			if jwkProvider.Issuer == issuer {
				if jwkProvider.JWKURL != "" {
					keySet, err := getKeySetFromJWKCache(jwkProvider.JWKURL)
					if err == nil && keySet != nil {
						issuerCache[issuer] = keySet
					}
					return keySet, err
				}
				if jwkProvider.DiscoverURL != "" {
					keySet, err := getKeySetFromDiscoverURLCache(jwkProvider.DiscoverURL)
					if err == nil && keySet != nil {
						issuerCache[issuer] = keySet
					}
					return keySet, err
				}

				return nil, nil
			}
		}
	}
	return nil, nil
}

func getJWKsURL(discoverURL string) (string, error) {
	resp, err := http.Get(discoverURL)
	if err != nil {
		resErr := fmt.Errorf("Error while getting openid connect configuration: %v", err)
		return "", resErr
	}

	decoder := json.NewDecoder(resp.Body)
	var config map[string]interface{}
	err = decoder.Decode(&config)
	if err != nil {
		resErr := fmt.Errorf("Error while parsing openid connect configuration: %v", err)
		return "", resErr
	}
	return config["jwks_uri"].(string), nil
}

func getDiscoverURL(issuer string) (string, error) {
	var discoverURL string
	if strings.HasSuffix(issuer, "/") {
		discoverURL = fmt.Sprintf("%s.well-known/openid-configuration", issuer)
	} else {
		discoverURL = fmt.Sprintf("%s/.well-known/openid-configuration", issuer)
	}
	dcvURL, err := url.Parse(discoverURL)
	if err != nil {
		return "", fmt.Errorf("Error while getting discover url from issuer claim: %v", err)
	}
	if dcvURL.Scheme == "" {
		dcvURL.Scheme = "https"
	}
	return dcvURL.String(), nil
}

func refreshCaches() {
	for jwksURL := range jwksCache {
		delete(jwksCache, jwksURL)
		keySet, err := getKeySet(jwksURL)
		if err != nil || keySet == nil {
			// TODO: maybe something else?
			continue
		}
	}

	for discoverURL := range discoverURLsCache {
		delete(discoverURLsCache, discoverURL)
		keySet, err := getKeySetFromDiscoverURLCache(discoverURL)
		if err != nil || keySet == nil {
			// TODO: maybe something else?
			continue
		}
	}

	for issuer := range issuerCache {
		delete(issuerCache, issuer)
		keySet, err := getKeySetFromIssuerCache(issuer)
		if err != nil || keySet == nil {
			// TODO: maybe something else?
			continue
		}
	}
}

// Init initializes fetch jwt package
func Init(providers []JWKProvider) error {
	if providers != nil {
		jwkProviders = providers
		for _, jwkProvider := range jwkProviders {
			if jwkProvider.Issuer != "" {
				issuerCache[jwkProvider.Issuer] = nil
			}
			if jwkProvider.DiscoverURL != "" {
				discoverURLsCache[jwkProvider.DiscoverURL] = nil
			}
			if jwkProvider.JWKURL != "" {
				jwksCache[jwkProvider.JWKURL] = nil
			}
		}
		refreshCaches()
	}

	c := cron.New()
	err := c.AddFunc("@every 24h", refreshCaches)
	if err != nil {
		return fmt.Errorf("failed to schedule JWKs refresh job: %v", err)
	}
	c.Start()
	return nil
}
