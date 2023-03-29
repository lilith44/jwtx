package jwtx

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type extraValidateFunc func(token *jwt.Token) bool

type JWT struct {
	method     string
	key        []byte
	scheme     string
	expiration time.Duration
	keyFunc    jwt.Keyfunc
}

// New returns a new jwt object.
func New(config Config, extra ...extraValidateFunc) *JWT {
	return &JWT{
		method:     config.Method,
		key:        []byte(config.Key),
		scheme:     config.Scheme,
		expiration: config.Expiration,
		keyFunc: func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != config.Method {
				return nil, jwt.ErrInvalidKey
			}

			standard, ok := token.Claims.(*jwt.StandardClaims)
			if !ok {
				return nil, jwt.ErrInvalidKey
			}

			if err := standard.Valid(); err != nil {
				return nil, err
			}

			for _, e := range extra {
				if e(token) {
					return nil, jwt.ErrInvalidKey
				}
			}

			return []byte(config.Key), nil
		},
	}
}

// Sign signs a jwt by payload.
func (j *JWT) Sign(payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	now := time.Now()
	token := jwt.NewWithClaims(
		jwt.GetSigningMethod(j.method),
		&jwt.StandardClaims{
			ExpiresAt: now.Add(time.Duration(j.expiration) * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			Subject:   string(data),
		},
	)

	var tokenString string
	if tokenString, err = token.SignedString(j.key); err != nil {
		return "", err
	}

	if j.scheme != "" {
		tokenString = j.scheme + tokenString
	}

	return tokenString, nil
}

// Payload extracts from the tokenString and unmarshals into payload.
func (j *JWT) Payload(tokenString string, payload any) error {
	if j.scheme != "" {
		tokenString = strings.TrimPrefix(tokenString, j.scheme)
	}

	standard := new(jwt.StandardClaims)
	_, err := jwt.ParseWithClaims(tokenString, standard, j.keyFunc)
	if err != nil {
		return err
	}

	if err = json.Unmarshal([]byte(standard.Subject), payload); err != nil {
		return err
	}

	return nil
}
