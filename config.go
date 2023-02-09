package jwtx

// Config is a config of jwt.
type Config struct {
	// signing method
	Method string `default:"HS256" yaml:"method" validate:"required,oneof=HS256 HS384 HS512"`
	Key    string `yaml:"key" validate:"required"`
	Scheme string `yaml:"scheme"`
	// minute
	Expiration int `default:"720" yaml:"expiration" validate:"required"`
}
