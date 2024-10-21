package test

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/getAlby/lsat-middleware/caveat"
	"github.com/getAlby/lsat-middleware/echolsat"
	"github.com/getAlby/lsat-middleware/ln"
	"github.com/getAlby/lsat-middleware/lsat"
	macaroonutils "github.com/getAlby/lsat-middleware/macaroon"
	"github.com/getAlby/lsat-middleware/middleware"
	"github.com/getAlby/lsat-middleware/utils"

	"github.com/labstack/echo/v4"

	"github.com/appleboy/gofight/v2"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func echoLsatHandler(lsatmiddleware *echolsat.EchoLsat) *echo.Echo {
	router := echo.New()

	router.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusAccepted, map[string]interface{}{
			"code":    http.StatusAccepted,
			"message": lsat.FREE_CONTENT_MESSAGE,
		})
	})

	router.Use(lsatmiddleware.Handler)

	router.GET("/protected", func(c echo.Context) error {
		lsatInfo := c.Get("L402").(*lsat.LsatInfo)
		if lsatInfo.Type == lsat.LSAT_TYPE_FREE {
			return c.JSON(http.StatusAccepted, map[string]interface{}{
				"code":    http.StatusAccepted,
				"message": lsat.FREE_CONTENT_MESSAGE,
			})
		}
		if lsatInfo.Type == lsat.LSAT_TYPE_PAID {
			return c.JSON(http.StatusAccepted, map[string]interface{}{
				"code":    http.StatusAccepted,
				"message": lsat.PROTECTED_CONTENT_MESSAGE,
			})
		}
		if lsatInfo.Type == lsat.LSAT_TYPE_ERROR {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"code":    http.StatusInternalServerError,
				"message": fmt.Sprint(lsatInfo.Error),
			})
		}
		return nil
	})

	return router
}

func TestEchoLsatWithLNURLConfig(t *testing.T) {

	err := godotenv.Load(".env")
	assert.NoError(t, err)

	LNURL_ADDRESS := os.Getenv("LNURL_ADDRESS")

	lnClientConfig := &ln.LNClientConfig{
		LNClientType: "LNURL",
		LNURLConfig: ln.LNURLoptions{
			Address: LNURL_ADDRESS,
		},
		RootKey: []byte(ROOT_KEY),
	}
	fr := &FiatRateConfig{
		Currency: "USD",
		Amount:   0.01,
	}
	lsatmiddleware, err := middleware.NewLsatMiddleware(lnClientConfig, fr.FiatToBTCAmountFunc, PathCaveat)
	assert.NoError(t, err)

	echolsatmiddleware := &echolsat.EchoLsat{
		Middleware: *lsatmiddleware,
	}

	handler := echoLsatHandler(echolsatmiddleware)

	router := gofight.New()

	router.GET("/").
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.FREE_CONTENT_MESSAGE, message)
			assert.Equal(t, http.StatusAccepted, res.Code)
		})

	router.GET("/protected").
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.FREE_CONTENT_MESSAGE, message)
			assert.Equal(t, http.StatusAccepted, res.Code)
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			lsat.LSAT_HEADER_NAME: lsat.LSAT_HEADER,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.PAYMENT_REQUIRED_MESSAGE, message)
			assert.Equal(t, http.StatusPaymentRequired, res.Code)

			assert.True(t, strings.HasPrefix(res.HeaderMap.Get("Www-Authenticate"), "L402 macaroon="))
			assert.True(t, strings.Contains(res.HeaderMap.Get("Www-Authenticate"), "invoice="))
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			"Authorization": fmt.Sprintf("L402 %s:%s", TEST_MACAROON_VALID, TEST_PREIMAGE_VALID),
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.PROTECTED_CONTENT_MESSAGE, message)
			assert.Equal(t, http.StatusAccepted, res.Code)
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			"Authorization": fmt.Sprintf("L402 %s:%s", TEST_MACAROON_VALID, TEST_PREIMAGE_INVALID),
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			macaroon, _ := utils.GetMacaroonFromString(TEST_MACAROON_VALID)

			macaroonId, _ := macaroonutils.GetMacIdFromMacaroon(macaroon)

			assert.Equal(t, fmt.Sprintf("Invalid Preimage %s for PaymentHash %s", TEST_PREIMAGE_INVALID, macaroonId.PaymentHash), message)
			assert.Equal(t, http.StatusInternalServerError, res.Code)
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			"Authorization": fmt.Sprintf("L402 %s:%s", TEST_MACAROON_WITHOUT_CAVEATS, TEST_MACAROON_WITHOUT_CAVEATS_PREIMAGE),
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, fmt.Sprintf("Caveats don't match"), message)
			assert.Equal(t, http.StatusInternalServerError, res.Code)
		})
}

func TestEchoLsatWithLNDConfig(t *testing.T) {

	err := godotenv.Load(".env")
	assert.NoError(t, err)

	LND_ADDRESS := os.Getenv("LND_ADDRESS")
	MACAROON_HEX := os.Getenv("MACAROON_HEX")

	lnClientConfig := &ln.LNClientConfig{
		LNClientType: "LND",
		LNDConfig: ln.LNDoptions{
			Address:     LND_ADDRESS,
			MacaroonHex: MACAROON_HEX,
		},
		RootKey: []byte(ROOT_KEY),
	}
	fr := &FiatRateConfig{
		Currency: "USD",
		Amount:   0.01,
	}
	lsatmiddleware, err := middleware.NewLsatMiddleware(lnClientConfig, fr.FiatToBTCAmountFunc, PathCaveat)
	assert.NoError(t, err)

	echolsatmiddleware := &echolsat.EchoLsat{
		Middleware: *lsatmiddleware,
	}

	handler := echoLsatHandler(echolsatmiddleware)

	router := gofight.New()

	router.GET("/").
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.FREE_CONTENT_MESSAGE, message)
			assert.Equal(t, http.StatusAccepted, res.Code)
		})

	router.GET("/protected").
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.FREE_CONTENT_MESSAGE, message)
			assert.Equal(t, http.StatusAccepted, res.Code)
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			lsat.LSAT_HEADER_NAME: lsat.LSAT_HEADER,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.PAYMENT_REQUIRED_MESSAGE, message)
			assert.Equal(t, http.StatusPaymentRequired, res.Code)

			assert.True(t, strings.HasPrefix(res.HeaderMap.Get("Www-Authenticate"), "L402 macaroon="))
			assert.True(t, strings.Contains(res.HeaderMap.Get("Www-Authenticate"), "invoice="))
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			"Authorization": fmt.Sprintf("L402 %s:%s", TEST_MACAROON_VALID, TEST_PREIMAGE_VALID),
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, lsat.PROTECTED_CONTENT_MESSAGE, message)
			assert.Equal(t, http.StatusAccepted, res.Code)
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			"Authorization": fmt.Sprintf("L402 %s:%s", TEST_MACAROON_VALID, TEST_PREIMAGE_INVALID),
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			macaroon, _ := utils.GetMacaroonFromString(TEST_MACAROON_VALID)

			macaroonId, _ := macaroonutils.GetMacIdFromMacaroon(macaroon)

			assert.Equal(t, fmt.Sprintf("Invalid Preimage %s for PaymentHash %s", TEST_PREIMAGE_INVALID, macaroonId.PaymentHash), message)
			assert.Equal(t, http.StatusInternalServerError, res.Code)
		})

	router.GET("/protected").
		SetHeader(gofight.H{
			"Authorization": fmt.Sprintf("L402 %s:%s", TEST_MACAROON_WITHOUT_CAVEATS, TEST_MACAROON_WITHOUT_CAVEATS_PREIMAGE),
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			message := fmt.Sprint(gjson.Get(res.Body.String(), "message"))

			assert.Equal(t, fmt.Sprintf("Caveats don't match"), message)
			assert.Equal(t, http.StatusInternalServerError, res.Code)
		})
}

func PathCaveat(req *http.Request) []caveat.Caveat {
	return []caveat.Caveat{
		{
			Condition: "RequestPath",
			Value:     req.URL.Path,
		},
	}
}
