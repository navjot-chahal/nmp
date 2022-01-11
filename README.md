# LoginID Go SDK

## About 
The server SDK to connect with LoginID's infrastructure

### Usage



Initialize a new `Loginid` client using a client ID, private key and base URL.
```go
import (
	"github.com/loginid1/go-sdk/loginid"
)

l, err := loginid.New(clientID, privateKey, baseURL)
if err != nil {
	// handle err
}
```

Initialize a new `Management` client using a client ID, private key and base URL.

```go
import (
	"github.com/loginid1/go-sdk/loginid/management"
)

m, err := management.New(clientID, privateKey, baseURL)
if err != nil {
	// handle err
}
```

## Quick start
Once the package is installed, you can import the package and connect to LoginID's backend

Refer to our documentations at
https://docs.loginid.io/Server-SDKs/Go/go-get-started for more details.

## Tell us how we’re doing
Have our solution in production? Tell us about your site on marketing@loginid.io and we’ll post on our social channels!