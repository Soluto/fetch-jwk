# fetch-jwk

[![Build Status](https://travis-ci.org/Soluto/fetch-jwk.svg?branch=master)](https://travis-ci.org/Soluto/fetch-jwk)

This library provides methods to fetch jwt keys from jwks url

## Rationale

If you're using library like [`jwt-go`](https://github.com/dgrijalva/jwt-go) for JWT validation you should supply [`Keyfunc`](https://godoc.org/github.com/dgrijalva/jwt-go#Keyfunc) that receives the JWT and returns public key for the JWT.

This library provides set of such key functions.

## Usage

In the following example the JWT `iss` claim is `test-issuer.com`. If the OpenID Connect server discovery page URL is `https://test-issuer.com/.well-known/openid-configuration` (just like Goodle or Azure AD are) you can use `FromIssuerClaim` key function.

Otherwise you can use `FromDiscoverURL` or `FromJWKsURL` functions.

```go
import (
    "fmt"
    jwkfetch "github.com/Soluto/fetch-jwk"
    jwt "github.com/dgrijalva/jwt-go"
)

var tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0LWlzc3Vlci5jb20iLCJhdWQiOiJ0ZXMtYXVkaWVuY2UifQ.dOUobGY8J6yxll7hGMWyQ9sVPsrCIjVNuFB1gsMhF4s"

token, err := jwt.Parse(tokenString, jwkfetch.FromIssuerClaim)

if token.Valid {
    fmt.Println("You look nice today")
} else if ve, ok := err.(*jwt.ValidationError); ok {
    if ve.Errors&jwt.ValidationErrorMalformed != 0 {
        fmt.Println("That's not even a token")
    } else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
        // Token is either expired or not active yet
        fmt.Println("Timing is everything")
    } else {
        fmt.Println("Couldn't handle this token:", err)
    }
} else {
    fmt.Println("Couldn't handle this token:", err)
}

```

## JWK Caching

JWK that were used for JWT validation are cached and used to validate another JWT with same issuer.

> Note: JWK are being changed usually every 24 hours. So the library refreshes the cache automatically every 24 hours.

If issuer or jwks_url are known in advance use [`Init`](https://godoc.org/github.com/Soluto/fetch-jwk#Init) method during your app startup.

## API Reference

API reference documentation is [here](https://godoc.org/github.com/Soluto/fetch-jwk).

## License

Licensed under [the MIT License](LICENSE)
