package echolsat

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/getAlby/lsat-middleware/caveat"
	"github.com/getAlby/lsat-middleware/ln"
	"github.com/getAlby/lsat-middleware/lsat"
	macaroonutils "github.com/getAlby/lsat-middleware/macaroon"
	"github.com/getAlby/lsat-middleware/middleware"
	"github.com/getAlby/lsat-middleware/utils"
	"github.com/lightningnetwork/lnd/lnrpc"

	"github.com/labstack/echo/v4"
)

type EchoLsat struct {
	Middleware middleware.LsatMiddleware
}

func (lsatmiddleware *EchoLsat) Handler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		//First check for presence of authorization header
		authField := c.Request().Header.Get("Authorization")
		caveats := []caveat.Caveat{}
		if lsatmiddleware.Middleware.CaveatFunc != nil {
			caveats = lsatmiddleware.Middleware.CaveatFunc(c.Request())
		}
		mac, preimage, err := utils.ParseLsatHeader(authField)
		if err != nil {
			// No Authorization present, check if client supports LSAT

			acceptLsatField := c.Request().Header.Get(lsat.LSAT_HEADER_NAME)

			if strings.Contains(acceptLsatField, lsat.LSAT_HEADER) {
				lsatmiddleware.SetLSATHeader(c, caveats)
				return nil
			}
			// Set LSAT type Free if client does not support LSAT
			c.Set(lsat.LSAT_HEADER, &lsat.LsatInfo{
				Type: lsat.LSAT_TYPE_FREE,
			})
			return next(c)
		}
		//LSAT Header is present, verify it
		err = lsat.VerifyLSAT(mac, caveats, lsatmiddleware.Middleware.RootKey, preimage)
		if err != nil {
			//not a valid LSAT
			c.Set(lsat.LSAT_HEADER, &lsat.LsatInfo{
				Type:  lsat.LSAT_TYPE_ERROR,
				Error: err,
			})
			return next(c)
		}
		//LSAT verification ok, mark client as having paid
		macaroonId, err := macaroonutils.GetMacIdFromMacaroon(mac)
		if err != nil {
			c.Set(lsat.LSAT_HEADER, &lsat.LsatInfo{
				Type:  lsat.LSAT_TYPE_ERROR,
				Error: err,
			})
			return next(c)
		}
		c.Set(lsat.LSAT_HEADER, &lsat.LsatInfo{
			Type:        lsat.LSAT_TYPE_PAID,
			Preimage:    preimage,
			PaymentHash: macaroonId.PaymentHash,
		})
		return next(c)
	}
}

func (lsatmiddleware *EchoLsat) SetLSATHeader(c echo.Context, caveats []caveat.Caveat) {
	// Generate invoice and token
	ctx := context.Background()
	lnInvoice := lnrpc.Invoice{
		Value: lsatmiddleware.Middleware.AmountFunc(c.Echo().AcquireContext().Request()),
		Memo:  lsat.LSAT_HEADER,
	}
	LNClientConn := &ln.LNClientConn{
		LNClient: lsatmiddleware.Middleware.LNClient,
	}
	invoice, paymentHash, err := LNClientConn.GenerateInvoice(ctx, lnInvoice, c.Echo().AcquireContext().Request())
	if err != nil {
		c.Set(lsat.LSAT_HEADER, &lsat.LsatInfo{
			Type:  lsat.LSAT_TYPE_ERROR,
			Error: err,
		})
		return
	}
	macaroonString, err := macaroonutils.GetMacaroonAsString(paymentHash, caveats, lsatmiddleware.Middleware.RootKey)
	if err != nil {
		c.Set(lsat.LSAT_HEADER, &lsat.LsatInfo{
			Type:  lsat.LSAT_TYPE_ERROR,
			Error: err,
		})
		return
	}
	c.Response().Header().Set("WWW-Authenticate", fmt.Sprintf("%s macaroon=%s, invoice=%s", lsat.LSAT_HEADER, macaroonString, invoice))
	c.JSON(http.StatusPaymentRequired, map[string]interface{}{
		"code":    http.StatusPaymentRequired,
		"message": lsat.PAYMENT_REQUIRED_MESSAGE,
	})
}
