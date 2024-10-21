package lsat

import (
	"fmt"

	"github.com/getAlby/lsat-middleware/caveat"
	macaroonutils "github.com/getAlby/lsat-middleware/macaroon"

	"github.com/lightningnetwork/lnd/lntypes"
	"gopkg.in/macaroon.v2"
)

const (
	LSAT_TYPE_FREE   = "FREE"
	LSAT_TYPE_PAID   = "PAID"
	LSAT_TYPE_ERROR  = "ERROR"
	LSAT_HEADER      = "L402"
	LSAT_HEADER_NAME = "Accept-Authenticate"
)

const (
	FREE_CONTENT_MESSAGE      = "Free Content"
	PROTECTED_CONTENT_MESSAGE = "Protected Content"
	PAYMENT_REQUIRED_MESSAGE  = "Payment Required"
)

type LsatInfo struct {
	Type        string
	Preimage    lntypes.Preimage
	PaymentHash lntypes.Hash
	Amount      int64
	Error       error
}

func VerifyLSAT(mac *macaroon.Macaroon, conditions []caveat.Caveat, rootKey []byte, preimage lntypes.Preimage) error {
	rawCaveats, err := mac.VerifySignature(rootKey, nil)
	if err != nil {
		return err
	}
	if err := caveat.VerifyCaveats(rawCaveats, conditions); err != nil {
		return err
	}
	macaroonId, err := macaroonutils.GetMacIdFromMacaroon(mac)
	if err != nil {
		return err
	}
	if macaroonId.PaymentHash != preimage.Hash() {
		return fmt.Errorf("Invalid Preimage %s for PaymentHash %s", preimage, macaroonId.PaymentHash)
	}
	return nil
}
