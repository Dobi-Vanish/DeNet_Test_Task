package token

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"reward/pkg/errormsg"
	"time"
)

type Validator struct {
	SecretKey string
}

// ValidateAccessToken validate provided access token.
func (ts *ServiceToken) ValidateAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("%w: %v", errormsg.ErrUnexpectedSigningMethod, t.Header["alg"])
		}

		return []byte(ts.SecretKey), nil
	})

	if err != nil {
		return nil, errormsg.ErrTokenValidation
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid { //nolint: nestif
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, errormsg.ErrTokenExpired
			}
		} else {
			return nil, errormsg.ErrInvalidTokenClaims
		}

		if iat, ok := claims["iat"].(float64); ok {
			if time.Now().Unix() < int64(iat) {
				return nil, errormsg.ErrTokenNotValidYet
			}
		} else {
			return nil, errormsg.ErrInvalidTokenClaims
		}

		return claims, nil
	}

	return nil, errormsg.ErrInvalidToken
}
