This package provides a simple, easy way to use jwt in your Go code.
# Usage
## Define your payload struct
```
type User struct {
	Id int64 `json:"id,string"`
}
```

## Create a jwt object
```
tool := jwtx.New(&jwtx.Config{
	Key:        "example",
	Scheme:     "Bearer ",
	Expiration: 10,
})
```

## Sign a jwt
```
token, _ := tool.Sign(&User{Id: 1})
```

## Extract from a jwt
```
user := new(User)
_ = tool.Payload(token, user)
```