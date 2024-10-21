# LSAT-Middleware

A middleware library for [Gin](https://github.com/gin-gonic/gin) and [Echo](https://echo.labstack.com/) framework that uses [L402, formerly known as LSAT](https://docs.lightning.engineering/the-lightning-network/l402) (a protocol standard for authentication and paid APIs) and provides handler functions to accept microtransactions before serving ad-free content or any paid APIs.

The middleware:-

1. Checks the preference of the user whether they need paid content or free content.
2. Verify the L402 before serving paid content.
3. Send macaroon and invoice if the user prefers paid content and fails to present a valid L402.

<img src="https://user-images.githubusercontent.com/44242169/186736015-f956dfe1-cba0-4dc3-9755-9d22cb1c7e77.jpg" width="700">


## Installation

Assuming you've installed Go and Gin 

1. Run this:

```
go get github.com/getAlby/lsat-middleware
```

2. Create `.env` file (refer `.env_example`) and configure `LND_ADDRESS` and `MACAROON_HEX` for LND client or `LNURL_ADDRESS` for LNURL client, `LN_CLIENT_TYPE` (out of LND, LNURL) and `ROOT_KEY` (for minting macaroons).  

## Usage

See the `examples` directory.

[This example](https://github.com/getAlby/lsat-middleware/blob/main/examples/ginlsat/main.go) shows how to use LSAT-Middleware with [Gin](https://github.com/gin-gonic/gin) framework for serving simple JSON response:-

[This repo](https://github.com/getAlby/lsat-proxy) demonstrates serving of static files and creating a paywall for paid resources using LSAT-Middleware.

[Nakaphoto](https://nakaphoto.vercel.app/), A platform to buy and sell images for sats made using LSAT-Middleware ([link to repo](https://github.com/getAlby/sell-lsat-files)).


## Testing

Run `go test` to run tests.
