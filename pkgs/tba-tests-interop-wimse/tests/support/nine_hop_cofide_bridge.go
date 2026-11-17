// B_CHAIN HTTP proof binding to the pinned Cofide POC and its httpsign library.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cofide/wimse-s2s-httpsig-poc/wimse/shared"
	"github.com/dunglas/httpsfv"
	"github.com/go-jose/go-jose/v4"
	"github.com/yaronf/httpsign"
)

const tag = "wimse-workload-to-workload"

type request struct {
	Command, Method, Audience, Target, Nonce, PrivateKey string
	Body                                                 []byte
	Headers                                              map[string]string
	PublicKey                                            jose.JSONWebKey
}

func run(input request) (map[string]string, error) {
	req, err := http.NewRequest(input.Method, input.Audience+input.Target, bytes.NewReader(input.Body))
	if err != nil {
		return nil, err
	}
	req.RequestURI = input.Target
	for name, value := range input.Headers {
		req.Header.Set(name, value)
	}
	fields := []string{"@method", "@request-target", "@authority"}
	for _, field := range []string{"content-type", "content-digest", "authorization", "txn-token", "workload-identity-token"} {
		if req.Header.Get(field) != "" || field == "content-digest" || field == "workload-identity-token" {
			fields = append(fields, field)
		}
	}
	schemes := []string{httpsign.DigestSha256}
	switch input.Command {
	case "sign":
		digest, err := httpsign.GenerateContentDigestHeader(&req.Body, schemes)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Digest", digest)
		fields = append([]string{"@method", "@path", "@query"}, fields[3:]...)
		signer, err := shared.GetWITHTTPSigner(input.PrivateKey, fields, shared.WithNonce(input.Nonce),
			func(config *httpsign.SignConfig) {
				config.SetExpires(time.Now().Add(time.Minute).Unix()).SignAlg(false).SetWIMSEAudience(input.Audience)
			})
		if err != nil {
			return nil, err
		}
		sigInput, sig, err := httpsign.SignRequest("wimse", *signer, req)
		return map[string]string{"Signature-Input": sigInput, "Signature": sig, "Content-Digest": digest}, err
	case "verify":
		if err := httpsign.ValidateContentDigestHeader(req.Header.Values("Content-Digest"), &req.Body, schemes); err != nil {
			return nil, fmt.Errorf("invalid request body digest: %w", err)
		}
		dict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
		if err != nil || len(dict.Names()) != 1 {
			return nil, fmt.Errorf("expected one WIMSE signature")
		}
		entry, _ := dict.Get("wimse")
		params, ok := entry.(httpsfv.InnerList)
		if !ok {
			return nil, fmt.Errorf("missing WIMSE signature parameters")
		}
		for _, name := range []string{"created", "expires"} {
			if _, ok := params.Params.Get(name); !ok {
				return nil, fmt.Errorf("missing WIMSE signature parameter %s", name)
			}
		}
		nonceValue, _ := params.Params.Get("nonce")
		nonce, ok := nonceValue.(string)
		if !ok || nonce == "" {
			return nil, fmt.Errorf("invalid WIMSE signature nonce")
		}
		config := httpsign.NewVerifyConfig().SetAllowedTags([]string{tag}).SetRejectExpired(true).SetVerifyCreated(true)
		if audience, ok := params.Params.Get("wimse-aud"); ok {
			// Authenticate the audience as part of the signature parameters.
			if audience != input.Audience {
				return nil, fmt.Errorf("WIMSE signature audience differs")
			}
			fields = append([]string{"@method", "@path", "@query"}, fields[3:]...)
		} else {
			if host := req.Header.Get("Host"); !strings.EqualFold(host, req.URL.Host) {
				return nil, fmt.Errorf("HTTP authority differs from configured service audience")
			}
			config.SetKeyID("wimse")
		}

		public, ok := input.PublicKey.Key.(*ecdsa.PublicKey)
		if !ok || public.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("expected a P-256 proof key")
		}
		verifier, err := httpsign.NewP256Verifier(*public, config, httpsign.Headers(fields...))
		if err != nil {
			return nil, err
		}
		if err := httpsign.VerifyRequest("wimse", *verifier, req); err != nil {
			return nil, err
		}
		return map[string]string{"nonce": nonce}, nil
	default:
		return nil, fmt.Errorf("unsupported operation")
	}
}

func main() {
	var input request
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := run(input)
	if err != nil {
		result = map[string]string{"denied": err.Error()}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
