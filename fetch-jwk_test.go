package jwkfetch

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

const httptestServerURL = "localhost:8888"

var discoverResponse = `{
	"jwks_uri": "http://localhost:8888/jwks"
}`

var jwkResponse = `{
	"keys": [
	  {
		"kid": "512fe2ae0e60bd03084b12885b41423f",
		"e": "AQAB",
		"kty": "RSA",
		"alg": "RS256",
		"n": "xL3TevYy9F9myjfAJw1dLV3LouuP8m24VlgWTehPypAce34YAprAHNWJhflKFCNQqqXRJEJYfyGn10K0OywIXrmpkq8-Sxmy3WmMT-DprKisP3YIbrW2gEm8BL8mQYyHosGQAFxM1ErhPtItiI56Avs7hj1bQ7SXJGElwqi19NqlN7sfoOUpTCuOp5E2wKRjMHKryi1pvPAXqxS58vDQ2no72d3Uoy1flQfK6pyCBqCMQkiP8ganuZV4oLaXEeS8e71w7HuoJ87o30r4J_WKAVwENwJJWhai1c_TvyWCCBFjEjdIDiQJaG4lGaaPV60mSHTGk2Sr_cf3aIKCbLGk0Q",
		"use": "sig"
	  }
	]
}`

func createTestServer(handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	l, _ := net.Listen("tcp", httptestServerURL)
	server.Listener = l
	server.Start()
	return server
}

func mockToken() *jwt.Token {
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodRS256.Alg(),
			"kid": "512fe2ae0e60bd03084b12885b41423f",
		},
		Claims: jwt.MapClaims{
			"iss": fmt.Sprintf("http://%s", httptestServerURL),
		},
		Method: jwt.SigningMethodRS256,
	}
	token.Header = map[string]interface{}{
		"kid": "512fe2ae0e60bd03084b12885b41423f",
	}
	return token
}

func mockKey() interface{} {
	var e, n big.Int

	eBuf, _ := base64.RawURLEncoding.DecodeString("AQAB")
	e.SetBytes(eBuf)

	nBuf, _ := base64.RawURLEncoding.DecodeString("xL3TevYy9F9myjfAJw1dLV3LouuP8m24VlgWTehPypAce34YAprAHNWJhflKFCNQqqXRJEJYfyGn10K0OywIXrmpkq8-Sxmy3WmMT-DprKisP3YIbrW2gEm8BL8mQYyHosGQAFxM1ErhPtItiI56Avs7hj1bQ7SXJGElwqi19NqlN7sfoOUpTCuOp5E2wKRjMHKryi1pvPAXqxS58vDQ2no72d3Uoy1flQfK6pyCBqCMQkiP8ganuZV4oLaXEeS8e71w7HuoJ87o30r4J_WKAVwENwJJWhai1c_TvyWCCBFjEjdIDiQJaG4lGaaPV60mSHTGk2Sr_cf3aIKCbLGk0Q")
	n.SetBytes(nBuf)
	key := &rsa.PublicKey{
		E: int(e.Int64()),
		N: &n,
	}
	return key
}

func Test_getKeyID(t *testing.T) {
	type args struct {
		token *jwt.Token
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "kid header doesn't exist",
			args: args{
				token: jwt.New(jwt.SigningMethodRS256),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "kid header is ok",
			args: args{
				token: func() *jwt.Token {
					token := jwt.New(jwt.SigningMethodRS256)
					token.Header["kid"] = "verySecretKey"
					return token
				}(),
			},
			want:    "verySecretKey",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getKeyID(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getKey(t *testing.T) {
	keySet, _ := jwk.ParseString(jwkResponse)
	type args struct {
		keySet *jwk.Set
		keyID  string
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "Happy flow",
			args: args{
				keySet: keySet,
				keyID:  "512fe2ae0e60bd03084b12885b41423f",
			},
			want: func() interface{} {
				key, _ := keySet.Keys[0].Materialize()
				return key
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getKey(tt.args.keySet, tt.args.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getKeySet(t *testing.T) {
	wantedKeySet, _ := jwk.ParseString(jwkResponse)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jwkResponse)
	}))
	defer server.Close()

	type args struct {
		jwksURL string
	}
	tests := []struct {
		name    string
		args    args
		want    *jwk.Set
		wantErr bool
	}{
		{
			name: "Google JWK endpoint is ok",
			args: args{
				jwksURL: fmt.Sprintf("%s/.well-known/openid-configuration", server.URL),
			},
			want:    wantedKeySet,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getKeySet(tt.args.jwksURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKeySet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getKeySet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getJWKsURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, discoverResponse)
	}))
	defer server.Close()

	type args struct {
		discoverURL string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Gets jwks_url from discover page",
			args: args{
				discoverURL: fmt.Sprintf("%s/.well-known/openid-configuration", server.URL),
			},
			want:    fmt.Sprintf("http://%s/jwks", httptestServerURL),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getJWKsURL(tt.args.discoverURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("getJWKsURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getJWKsURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDiscoverURL(t *testing.T) {
	type args struct {
		issuer string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "https://accounts.google.com",
			args: args{
				issuer: "https://accounts.google.com",
			},
			want:    "https://accounts.google.com/.well-known/openid-configuration",
			wantErr: false,
		},
		{
			name: "https://accounts.google.com/",
			args: args{
				issuer: "https://accounts.google.com/",
			},
			want:    "https://accounts.google.com/.well-known/openid-configuration",
			wantErr: false,
		},
		{
			name: "http://accounts.google.com/",
			args: args{
				issuer: "http://accounts.google.com/",
			},
			want:    "http://accounts.google.com/.well-known/openid-configuration",
			wantErr: false,
		},
		{
			name: "accounts.google.com/",
			args: args{
				issuer: "accounts.google.com/",
			},
			want:    "https://accounts.google.com/.well-known/openid-configuration",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDiscoverURL(tt.args.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDiscoverURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getDiscoverURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromIssuerClaim(t *testing.T) {
	server := createTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, discoverResponse)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/jwks") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, jwkResponse)
			return
		}
	}))
	defer server.Close()

	type args struct {
		token *jwt.Token
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "Happy flow",
			args: args{
				token: mockToken(),
			},
			want:    mockKey(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFunc := FromIssuerClaim()
			got, err := keyFunc(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromIssuerClaim() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromIssuerClaim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromDiscoverURL(t *testing.T) {
	server := createTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, discoverResponse)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/jwks") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, jwkResponse)
			return
		}
	}))
	defer server.Close()

	type args struct {
		discoverURL string
		token       *jwt.Token
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "Happy flow",
			args: args{
				token:       mockToken(),
				discoverURL: fmt.Sprintf("http://%s/.well-known/openid-configuration", httptestServerURL),
			},
			want:    mockKey(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFunc := FromDiscoverURL(tt.args.discoverURL)
			got, err := keyFunc(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromDiscoverURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromDiscoverURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromJWKsURL(t *testing.T) {
	server := createTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jwks") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, jwkResponse)
			return
		}
	}))
	defer server.Close()

	type args struct {
		jwksURL string
		token   *jwt.Token
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "Happy flow",
			args: args{
				token:   mockToken(),
				jwksURL: fmt.Sprintf("http://%s/jwks", httptestServerURL),
			},
			want:    mockKey(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFunc := FromJWKsURL(tt.args.jwksURL)
			got, err := keyFunc(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromJWKsURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromJWKsURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
