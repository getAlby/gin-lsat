package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/getAlby/lsat-middleware/caveat"
	"github.com/getAlby/lsat-middleware/ginlsat"
	"github.com/getAlby/lsat-middleware/ln"
	"github.com/getAlby/lsat-middleware/lsat"
	"github.com/getAlby/lsat-middleware/middleware"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
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
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusAccepted, gin.H{
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
	lsatmiddleware, err := middleware.NewLsatMiddleware(lnClientConfig, fr.FiatToBTCAmountFunc, PathCaveat)
	if err != nil {
		log.Fatal(err)
	}
	ginlsatmiddleware := &ginlsat.GinLsat{
		Middleware: *lsatmiddleware,
	}

	router.Use(ginlsatmiddleware.Handler)

	router.GET("/protected", func(c *gin.Context) {
		lsatInfo := c.Value("LSAT").(*lsat.LsatInfo)
		if lsatInfo.Type == lsat.LSAT_TYPE_FREE {
			c.JSON(http.StatusAccepted, gin.H{
				"code":    http.StatusAccepted,
				"message": "Free content",
			})
		} else if lsatInfo.Type == lsat.LSAT_TYPE_PAID {
			c.JSON(http.StatusAccepted, gin.H{
				"code":    http.StatusAccepted,
				"message": "Protected content",
			})
		} else if lsatInfo.Type == lsat.LSAT_TYPE_ERROR {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": fmt.Sprint(lsatInfo.Error),
			})
		}
	})
	router.GET("/protected/2", func(c *gin.Context) {
		lsatInfo := c.Value("LSAT").(*lsat.LsatInfo)
		if lsatInfo.Type == lsat.LSAT_TYPE_FREE {
			c.JSON(http.StatusAccepted, gin.H{
				"code":    http.StatusAccepted,
				"message": "Free content",
			})
		} else if lsatInfo.Type == lsat.LSAT_TYPE_PAID {
			c.JSON(http.StatusAccepted, gin.H{
				"code":    http.StatusAccepted,
				"message": "Protected content",
			})
		} else if lsatInfo.Type == lsat.LSAT_TYPE_ERROR {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": fmt.Sprint(lsatInfo.Error),
			})
		}
	})

	router.Run("localhost:8080")
}

func PathCaveat(req *http.Request) []caveat.Caveat {
	return []caveat.Caveat{
		{
			Condition: "RequestPath",
			Value:     req.URL.Path,
		},
	}
}
