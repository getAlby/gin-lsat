package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/getAlby/lsat-middleware/echolsat"
	"github.com/getAlby/lsat-middleware/ln"
	"github.com/getAlby/lsat-middleware/lsat"
	"github.com/getAlby/lsat-middleware/middleware"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

const SATS_PER_BTC = 100000000

const MIN_SATS_TO_BE_PAID = 1

type FiatRateConfig struct {
	Currency string
	Amount   float64
}

func (fr *FiatRateConfig) FiatToBTCAmountFunc(req *http.Request) (amount int64) {
	if req == nil {
		return MIN_SATS_TO_BE_PAID
	}
	res, err := http.Get(fmt.Sprintf("https://blockchain.info/tobtc?currency=%s&value=%f", fr.Currency, fr.Amount))
	if err != nil {
		return MIN_SATS_TO_BE_PAID
	}
	defer res.Body.Close()

	amountBits, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return MIN_SATS_TO_BE_PAID
	}
	amountInBTC, err := strconv.ParseFloat(string(amountBits), 32)
	if err != nil {
		return MIN_SATS_TO_BE_PAID
	}
	amountInSats := SATS_PER_BTC * amountInBTC
	return int64(amountInSats)
}

func main() {
	router := echo.New()

	router.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusAccepted, map[string]interface{}{
			"code":    http.StatusAccepted,
			"message": "Free content",
		})
	})

	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Failed to load .env file")
	}

	var lnClientConfig *ln.LNClientConfig
	clientType := os.Getenv("LN_CLIENT_TYPE")

	switch clientType {
	case "LND":
		lnClientConfig = &ln.LNClientConfig{
			LNClientType: clientType,
			LNDConfig: ln.LNDoptions{
				Address:     os.Getenv("LND_ADDRESS"),
				MacaroonHex: os.Getenv("MACAROON_HEX"),
			},
			RootKey: []byte(os.Getenv("ROOT_KEY")),
		}
	case "LNURL":
		lnClientConfig = &ln.LNClientConfig{
			LNClientType: clientType,
			LNURLConfig: ln.LNURLoptions{
				Address: os.Getenv("LNURL_ADDRESS"),
			},
			RootKey: []byte(os.Getenv("ROOT_KEY")),
		}
	default:
		log.Fatalf("Invalid LN_CLIENT_TYPE: %s. Must be either 'LND' or 'LNURL'.", clientType)
	}

	fr := &FiatRateConfig{
		Currency: "USD",
		Amount:   0.01,
	}
	lsatmiddleware, err := middleware.NewLsatMiddleware(lnClientConfig, fr.FiatToBTCAmountFunc, nil)
	if err != nil {
		log.Fatal(err)
	}
	echolsatmiddleware := &echolsat.EchoLsat{
		Middleware: *lsatmiddleware,
	}

	router.Use(echolsatmiddleware.Handler)

	router.GET("/protected", func(c echo.Context) error {
		lsatInfo := c.Get("LSAT").(*lsat.LsatInfo)
		if lsatInfo.Type == lsat.LSAT_TYPE_FREE {
			return c.JSON(http.StatusAccepted, map[string]interface{}{
				"code":    http.StatusAccepted,
				"message": "Free content",
			})
		}
		if lsatInfo.Type == lsat.LSAT_TYPE_PAID {
			return c.JSON(http.StatusAccepted, map[string]interface{}{
				"code":    http.StatusAccepted,
				"message": "Protected content",
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

	router.Start("localhost:8080")
}
