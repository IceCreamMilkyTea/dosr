// Package notary implements DOSR's attesting proxy ("notary") and its
// client.
//
// # TRUST MODEL - READ THIS FIRST
//
// The notary in this prototype is a TRUSTED PROXY. It is NOT a TLSNotary
// notary:
//
//   - It terminates TLS to the LLM provider itself and therefore SEES ALL
//     PLAINTEXT of the API call: the request, the response and the
//     contributor's API KEY. A contributor must trust the notary operator
//     with that key (or use a key scoped/budgeted for this purpose). In
//     real TLSNotary the notary takes part in an MPC-TLS session and never
//     sees plaintext or the key.
//   - Validators trust the notary's signature completely. A malicious or
//     compromised notary can attest API calls that never happened
//     (forging approvals). Validators cannot detect this; the policy's
//     list of notary keys is the root of trust. With real TLSNotary a
//     dishonest notary alone cannot forge a transcript either, as long as
//     it does not collude with the prover.
//   - The notary's clock is trusted for the attestation time.
//
// What the design does preserve is the shape of the verifier-facing
// object (package attest): a signed commitment to the transcript plus a
// selective opening. Validators never see the API key: the contributor
// presents the x-api-key header as a Hidden leaf (BuildPresentation).
//
// # Protocol
//
//	POST /v1/attest   {"url":"https://host[:port]/path","method":"POST",
//	                   "headers":{name:value},"body":<base64>}
//	               -> {"attestation":{...},"secret":{...},"timing":{...}}
//	GET  /v1/info  -> {"version":1,"notary_key":<base64>,"allowed_hosts":[...],...}
//
// Errors are JSON {"error":{"code":"...","message":"..."}} with a 4xx/5xx
// status; see the Code* constants.
//
// The notary's own listener speaks plain HTTP unless Config.TLS is set.
// Plain HTTP is acceptable ONLY on localhost / a trusted network, because
// the attest request carries the API key and the response carries the
// secret (salts and values). This is a prototype simplification.
//
// # The transcript (normative)
//
// The notary makes exactly one HTTP/1.1 request on a fresh TLS connection
// (TLS >= 1.2, ALPN "http/1.1", certificate validated against the
// configured roots for the URL's host name) and attests these fields, in
// this order:
//
//	req.method            the method, upper case ("POST")
//	req.path              the request target exactly as sent: escaped path
//	                      plus "?query" if the URL has a query
//	req.header.<name>...  EVERY header line the notary wrote on the wire,
//	                      names lower case, sorted by name, each name once
//	req.body              the request body bytes
//	resp.status           the status code in decimal ("200")
//	resp.header.<name>... the end-to-end response headers, names lower
//	                      case, sorted by name
//	resp.body             the response body after removing the transfer
//	                      coding (de-chunked)
//
// Request headers. The notary writes the caller's headers plus four of
// its own, which the caller cannot change (supplying one of them with a
// different value is an error):
//
//	host: <host[:port]>        the URL's authority, lower case, ":443" omitted
//	accept-encoding: identity  so that the body is not compressed
//	connection: close          one request per connection
//	content-length: <n>        length of the body (always present for POST)
//
// Nothing else is sent (no default user-agent). Hop-by-hop and framing
// headers (transfer-encoding, te, trailer, upgrade, keep-alive, expect,
// proxy-*) are rejected in requests. Header names must be unique after
// lower-casing; values must not contain control characters.
//
// Response headers. Multi-valued headers (several lines with the same
// name) are combined into one field whose value is the values joined with
// ", " in the order received (RFC 9110 section 5.3). This is well-defined
// but not injective (["a, b"] and ["a","b"] give the same field); DOSR
// gives response headers no authority, so this is harmless. Excluded from
// the transcript, because they describe the connection or the framing
// rather than the message: connection, keep-alive, proxy-authenticate,
// proxy-authorization, proxy-connection, te, trailer, transfer-encoding,
// upgrade, every header named by the response's Connection header, and
// content-length (implied by resp.body; absent for chunked responses, so
// dropping it makes chunked and non-chunked responses attest alike).
// "date" IS included (it is an end-to-end header and records the
// provider's clock). Trailers of chunked responses are ignored.
//
// A response with a content-encoding other than "identity" is rejected
// (the contract defines resp.body as the unencoded body and the notary
// asked for identity). 1xx interim responses are skipped; 101 is rejected.
//
// Redirects are NEVER followed: a 3xx response is attested as-is, like
// any other status. It is the verifier's job to require resp.status ==
// "200". (Following redirects would let the provider, or anyone able to
// plant a redirect, steer the notary to other hosts.)
//
// Header.ServerName is the URL's host name WITHOUT port (the name the
// certificate was verified for); the port is bound by req.header.host.
// Header.ServerSPKI is SHA-256 of the leaf certificate's
// SubjectPublicKeyInfo. Header.Time is the notary's clock when the
// response was complete.
//
// # SSRF hardening
//
// Only https URLs whose canonical authority (host[:port]) is on the
// allow-list are contacted; URLs with userinfo or fragments are rejected;
// no redirects are followed; the server certificate must be valid for the
// host name under the configured roots; response size and total time are
// bounded.
//
// # Single-use review nonces (anti approval-grinding)
//
// See nonce.go. With Config.EnforceSingleUseNonce the notary attests at
// most one API call per DOSR review nonce.
package notary
