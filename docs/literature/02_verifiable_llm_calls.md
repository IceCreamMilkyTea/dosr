# 2. Verifiable Provenance of TLS/API Data and Verifiable LLM Inference

*DOSR literature review, section 2. All sources were fetched on 2026-09-29. Claims are tagged with reference numbers; anything that could not be confirmed from a fetched source is listed in Section 2.9 rather than asserted.*

## 2.1 Problem statement

DOSR needs a Byzantine contributor to convince BFT validators that a specific HTTPS request (canonical diff plus review prompt) sent to a hosted LLM API produced a specific response (approve/reject), without validators re-running the model and without the contributor revealing the API key.

TLS alone cannot provide this. TLS authenticates application data with symmetric keys that both endpoints hold, so the client "can trivially generate fake transcripts locally" [T3]. The server never signs the bytes. Every system below therefore adds a second party who is present *during* the session (an MPC co-client, a proxy, or an enclave) and who later vouches for what was exchanged. The systems differ in what that witness sees and what must be assumed about it.

DOSR needs **provenance of an API response**, not a proof that a computation was performed correctly. That distinction rules out an entire family of techniques (Section 2.5).

## 2.2 TLSNotary

### 2.2.1 Current state of the project

The reference implementation is `tlsnotary/tlsn` (Rust, MIT/Apache-2.0). Its README states that the project "is currently under active development and should not be used in production. Expect bugs and regular major breaking changes" [T1]. The latest tagged release is **v0.1.0-alpha.15**, published 2026-05-21 and marked as a pre-release; the `main` branch is versioned `0.1.0-alpha.16-pre` [T2][T1]. Every release since alpha.4 has been a pre-release, and release notes routinely announce breaking API changes [T2].

**TLS support.** The docs state "TLSNotary currently supports TLS 1.2. Support for TLS 1.3 is on the roadmap", and elsewhere "There are no immediate plans to support TLS 1.3" [T3]. In the source, the list of enabled ciphersuites contains exactly two entries, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; the TLS 1.3, AES-256-GCM and ChaCha20-Poly1305 suites are commented out [T4].

### 2.2.2 MPC-TLS message flow

1. **Handshake.** The Prover opens the TCP connection to the Server and "physically communicates" with it, "but all cryptographic TLS operations are performed together with the Verifier using MPC". The two parties compute the session key "in such a way that both only have their share of the key and never learn the full key" [T5]. The server sees an ordinary TLS client.
2. **Request encryption.** Both parties input key shares; the Prover also inputs the plaintext privately. Both see the resulting ciphertext and jointly compute the MAC. The Prover sends the record to the server [T6].
3. **Response decryption.** The parties jointly verify the server's MAC, then decrypt; "the resulting plaintext is revealed ONLY to the Prover" [T6]. With *deferred decryption* (the default), ciphertext is buffered and, after the connection closes, the Verifier reveals its key share so the Prover decrypts locally. This is safe because by then "the ciphertext-plus-MAC is already committed" [T7].
4. **Selective disclosure.** The Prover reveals chosen byte ranges of the transcript, or proves hash commitments (SHA-256, BLAKE3, Keccak-256) over ranges, using the interactive QuickSilver VOLE-based ZK system rather than a zkSNARK [T3][T2].

The security claim is two-sided: a malicious Prover cannot convince the Verifier of false data, and a malicious Verifier cannot learn the Prover's private data [T3]. In MPC mode the Verifier learns only ciphertext plus metadata: session time, request/response lengths, number of round trips, and ciphersuite [T3].

### 2.2.3 Notary, attestation, presentation

If the party that needs convincing cannot be online, the in-session role is delegated to a **Notary**, which signs an **attestation**. In the current `tlsn-attestation` crate [T8] an attestation has:

- a **Header**, the object that is signed: a 16-byte unique id, a version, and the Merkle root of the body fields;
- a **Body** containing the notary verifying key, `ConnectionInfo` (UNIX time when the connection started, TLS version, sent/received transcript lengths), the server ephemeral public key, a commitment to the server certificate data, optional extensions, and the transcript commitments [T8][T9].

Each field is hashed with a domain separator and Merkleized, so a presentation needs to include only the fields it uses [T8][T2]. The Prover keeps private `Secrets` and later builds a **Presentation** that discloses chosen ranges plus a server identity proof. The verifier must (a) decide that it trusts the attestation's verifying key and (b) call `Presentation::verify`, which yields the server name, connection info, and the partial transcript with undisclosed bytes redacted [T8]. Verification can be compiled for targets without an OS random number generator, which the release notes explicitly motivate with "blockchains, or other restricted environments" [T2].

**Extensions** let the Prover or Notary bind custom data into the attestation; the release notes give the example of a Prover including their public key to bind the attestation to their identity [T2]. This is the natural hook for a DOSR nonce, PR identifier, or chain height.

### 2.2.4 Changes to the notary model

The task brief asked whether the notary model changed. It did, and the details matter:

- **alpha.11** (2025-05-27) deprecated the notarization methods in the core prover/verifier API, stating that "using our particular attestation model is optional" [T2].
- **alpha.13** (2025-10-15) removed `notary-server` and `notary-client` from the repository: "we are reducing focus on the issuance of attestations ... We believe the last-mile process of attestation issuance is best handled by users". The `tlsn-attestation` crate "will continue to be maintained but will not receive new features" [T2].
- **alpha.15** (2026-05-21) added a **proxy-TLS** mode alongside MPC-TLS, and HTTP chunked-transfer parsing [T2].

So attestations still exist as a library, and an `attestation` example remains in the repository [T1], but there is no maintained reference notary server. A DOSR deployment would have to build and operate its own notary service around the library.

### 2.2.5 Trust assumptions, including collusion

The FAQ's statement that "the protocol does not have trust assumptions" applies only to a Verifier that participates in the session itself. For delegated verification the same FAQ says verifiers "must trust in the notary's neutrality, ensuring it has not been influenced or compromised by the Prover" [T3].

The project's 2026 blog post is blunt: zkTLS is a **designated-verifier** protocol. Because the verifier participates, "it could have collaborated with the prover to fabricate the entire exchange"; on-chain "there is always a signature standing in for a proof" [T10]. Mitigations listed are M-of-N independent notaries, or staked and slashable notaries; a multi-party MPC notary "is not yet practical" [T10]. The FAQ also states that TLSNotary "does not solve the Oracle Problem" [T3].

For DOSR this is decisive. **A contributor who colludes with, or is, the notary can forge an approval.** The notary key set must be part of DOSR's trust base, for example validator-operated notaries with a quorum rule.

### 2.2.6 Published performance

- **Bandwidth formula (FAQ).** Expected Prover upload is "~25MB (a fixed cost per one TLSNotary session) + ~10 MB per every 1KB of outgoing data + ~40KB per every 1 KB of incoming data"; a 1 KB request with a 100 KB response costs about 39 MB of upload [T3]. The FAQ frames these as expectations for an upgrade "planned for 2025", so they should be read as approximate.
- **Asymmetry.** Request bytes are roughly 250 times more expensive than response bytes. All sent bytes must be encrypted under MPC while the server waits, so "there is no 'free' tier here" [T7]. *This is the worst case for DOSR, whose request carries the whole diff.* By the FAQ formula a 20 KB request would imply on the order of 200 MB of upload (our arithmetic, not a published measurement).
- **Runtime (May 2026 benchmarks, 1 KB request / 2 KB response, native build).** MPC: 14.5 s cable, 10.4 s mobile 5G, 3.6 s fiber. Proxy mode: 1.6 s, 1.6 s, 1.0 s. MPC uploads about 30 MB of preprocessing material before the handshake and uses about 40 communication rounds [T11].
- **Limits.** `max_sent_data` and `max_recv_data` must be fixed before the session and "exceeding it aborts the session" [T7]. The alpha.5 notes gave a default sent limit of 4 KB [T2]; alpha.13 reports that fully revealed responses can reach "the order of megabytes" [T2].
- **On-chain verification.** "At the moment the most practical way to verify data on-chain is to prove the data directly to an off-chain application-specific verifier" [T3].

## 2.3 DECO, Town Crier, and the zkTLS family

**Town Crier** (Zhang, Cecchetti, Croman, Juels, Shi) is a TEE oracle: an Intel SGX enclave fetches HTTPS data and relays it to smart contracts, supporting encrypted requests [R2]. Trust rests on the hardware vendor and enclave integrity.

**DECO** (Zhang, Maram, Malvai, Goldfeder, Juels; CCS 2020) claims to be the first such system "that works without trusted hardware or server-side modifications" [R1]. It has three phases [R1]:

1. **Three-party handshake.** Prover P and Verifier V jointly act as the TLS client and obtain the session key in secret-shared form. For CBC-HMAC, P and V hold shares of the MAC key and the server holds their sum.
2. **Query execution.** P and V run custom 2PC protocols to build the encrypted query (2PC-HMAC or 2PC-GCM). P commits to the session data, and only then does V reveal its key share. Unforgeability reduces to the MAC's unforgeability because P did not know the MAC key before committing.
3. **Proof generation.** P proves statements in zero knowledge, with *selective opening* and *context integrity* (proving a revealed substring appears in the right place in the JSON/HTML parse tree, so it cannot be quoted out of context).

The paper reports, for TLS 1.2 in a WAN setting, 2.85 s online for the handshake and 2.52 s for 2PC-HMAC query execution, with 3 to 13 s for application ZK proofs; 2PC-GCM on a 2 KB query took about 9.1 s online in WAN [R1]. Context integrity is directly relevant to DOSR: the verdict must be the model's output field, not a string the contributor planted inside the diff and then selectively revealed.

**Proxy mode** first appears in DECO's Appendix C.4: V proxies the traffic and records ciphertext, and P later proves statements about it. The paper states the cost plainly: V must have correct DNS records, and the network between V and the server "must be properly secured against traffic injection, e.g., through BGP attacks" [R1]. It also notes that GCM is not a committing cipher, so P must commit to its key share before learning the session key [R1].

**Later academic work** (verified at abstract level only):

- *Garble-then-Prove* (Xie, Yang, Wang, Yu; USENIX Security 2024) avoids generic malicious 2PC and reports a 14x communication improvement [R3]. TLSNotary adopted a result from this paper in alpha.6 [T2].
- *DiStefano* (Celi, Davidson, Haddadi, Pestana, Rowell) targets TLS 1.3 and is integrated into BoringSSL [R4].
- *Janus* (Lauinger et al., PoPETs 2025) optimizes garble-then-prove for TLS 1.3 [R5].
- *ORIGO* (Ernstberger et al.) is a proxy-setting TLS 1.3 oracle with constant online communication, claiming 375x less online communication than prior work; its introduction also analyzes attacks in the proxy setting [R6].
- *Proxying Is Enough* (Luo, Jia, Shen, Kate; AFT 2025) studies a pure forwarding proxy where the response may be visible to the verifier and only credentials are hidden. It proves integrity for HTTPS under stated conditions and shows that "ChaCha20-Poly1305 satisfies [context unforgeability] while AES-GCM does not" [R7].

**Industry.** "zkTLS" is the umbrella marketing term. TLSNotary's own blog uses it while stressing that the result is "a notarized attestation", and notes that the ecosystem calls the notary role an "attestor" [T10].

- *Reclaim Protocol* uses an attestor that proxies encrypted traffic, and cites Luo et al. as its security basis [I1].
- *Opacity* is described in a design note as two EigenLayer AVSs (MPC-TLS nodes and zkTLS oracles) whose operators must bind to an SGX device. To limit collusion, clients must "pre-commit what they wish to prove before the MPC-Node is selected" [I2].
- *zkPass* describes itself as "3P-TLS and Hybrid-ZK" using VOLE-in-the-Head [I3].
- *TLSNotary proxy mode* (alpha.15): the Verifier forwards and records ciphertext; afterwards the Prover proves in ZK the TLS 1.2 PRF derivation from the master secret and the server GHASH key, and the Verifier recomputes AES-GCM tags on every observed record. The docs state that if a third party operates the Verifier, "the Prover and the third-party Verifier must not collude — the same trust requirement as MPC-TLS" [T12].

## 2.4 TEE-based verifiable inference

**OpenGradient `tee-gateway`** is an LLM router that runs inside an AWS Nitro Enclave and forwards requests to OpenAI, Anthropic, Google, xAI and others [G1]. Its design:

- The enclave generates an RSA key; the Nitro attestation document carries PCR measurements and binds the public key, so clients verify AWS root certificate, then PCRs, then key.
- Each response carries `tee_request_hash` (keccak256 of the canonicalized request JSON), `tee_output_hash`, `tee_timestamp`, `tee_id`, and `tee_signature`, an RSA-PSS-SHA256 signature over `keccak256(requestHash || outputHash || timestamp)`.
- The README warns that PCR values differ if an operator builds its own image; clients must know which measurements correspond to honest code.

Two properties matter for DOSR. First, the **enclave terminates TLS and sees plaintext**, including the provider API key. In the repository's model the gateway holds provider credentials and is paid per request via x402, which differs from DOSR's bring-your-own-key model. Second, the signature covers request hash, output hash and timestamp, but binds no caller-chosen nonce in the signed tuple as documented; freshness rests on the timestamp (a nonce exists only for the attestation endpoint) [G1].

**Other gateways.** Phala's Confidential AI documentation describes GPU TEEs, a gateway attestation endpoint, and "a signed receipt" on every response [G2]. NEAR AI Cloud documents verification in terms of "quote, nonce, and signer bindings" [G3]. Neither page, as fetched, clearly states whether closed-weight third-party models are covered.

**What attestation does and does not prove.** TLSNotary's analysis of a production application that moved from proxy zkTLS to Nitro enclaves is a useful framing: integrity in both designs "end[s] at a delegated attestor's signature"; the TEE relocates trust from the operator to the hardware vendor; and "a measurement is a hash, not a meaning", since matching PCRs shows that the expected image loaded, not that the image is honest, which requires source and reproducible builds [T13]. The same post observes that the two compose: a zkTLS verifier can run inside an enclave [T13].

## 2.5 Cryptographic verifiable inference and why it does not apply

- **zkML.** EZKL compiles an ONNX graph into a Halo2 circuit and proves statements such as "I ran this neural network on private data and got this output"; quantization means circuit outputs can differ slightly from the floating-point model [Z1]. zkLLM (Sun, Li, Zhang; CCS 2024) reports proofs under 200 kB for a 13-billion-parameter model, generated in under 15 minutes with a CUDA implementation [Z2].
- **Optimistic ML.** opML (Conway, So, Yu, Wong) uses an interactive fraud-proof game in the style of optimistic rollups, and reports running a 7B LLaMA model on a standard PC [Z3].

All of these require that **the prover (and, for opML, the challengers) possess the model** and execute it in a deterministic, arithmetized form. Claude and GPT weights are not available to a contributor, the providers publish no proofs, and fraud-proof re-execution is impossible for a model nobody else can run. DOSR's statement is "provider endpoint X returned bytes Y for request Z", which is a TLS provenance statement. Even if zkML were applicable, zkLLM's prover time for one 13B-parameter inference is orders of magnitude above the 1 to 15 s of TLS oracles.

A corollary: no mechanism in this section proves which weights produced the answer. The validator learns only what the provider *said* (Section 2.6.5).

## 2.6 Threats specific to DOSR

### 2.6.1 Non-determinism and approval grinding

A certificate proves that *one* approving response exists. It says nothing about how many rejections preceded it. No source we fetched analyzes this attack for attested LLM calls; the mitigations below are design inferences, not literature results.

Evidence that determinism cannot be assumed:

- Atil et al. tested five LLMs "configured to be deterministic" and found accuracy variations up to 15% across runs, with no model giving repeatable outputs on all tasks [N1].
- Anthropic's documentation says model weights are fixed per ID but "sampling logic" and other serving infrastructure can change and "produce minor differences in observable behavior" [A2].
- The Anthropic Messages API now marks `temperature` as deprecated: "Models released after Claude Opus 4.6 do not support setting temperature"; only 1.0 is accepted, and other values return a 400 error [A1]. **A DOSR policy of "temperature 0" is therefore not even expressible on current Claude models.**

Since the verdict is a random variable, the design goal is to **bound the number of samples per PR state**:

1. *Registered review intent.* The contributor first commits on-chain to (repo, base commit, diff hash, prompt version, model ID). Validators accept only certificates that reference a registered intent, with at most k intents per PR state.
2. *Chain-derived nonce.* The intent's inclusion yields a nonce from later chain randomness, which must appear in the revealed request. The contributor cannot pre-compute approvals before committing. Opacity's rule of committing before the notary is selected is the closest published analogue [I2].
3. *Notary-side counting.* If notaries are validator-operated, they can refuse to co-sign more than k sessions per intent. This is the only mitigation that restricts attempts rather than merely pricing them.
4. *k-of-n providers or repeated samples*, which reduce single-sample variance at proportional cost.
5. *Fees or stake per intent.*

Residual risk: the MPC-TLS notary is blind to plaintext and to the server identity [T3], so it cannot by itself tell which PR a session belongs to. Counting requires the Prover to bind the intent into the attestation (an extension field) before the session.

### 2.6.2 Prompt injection in the diff

Greshake et al. show that LLM-integrated applications "blur the line between data and instructions", enabling indirect injection through retrieved content [P1]. OWASP LLM01:2025 lists mitigations: constrain behavior in the system prompt, define and validate output formats, filter input and output, segregate and mark external content, and require human approval for high-risk actions [P2]. None is a guarantee.

A provenance certificate faithfully attests to a manipulated verdict. It proves the model said "approve", not that the code is safe. The certificate should therefore reveal the full request so that any validator or auditor can inspect the diff for injected instructions, and the verdict must be read from a structured output field with context integrity [R1].

### 2.6.3 Replay and freshness

A TLSNotary attestation carries the connection start time and a unique attestation id [T8][T9], but nothing about the application. Freshness for DOSR must come from content inside the signed request: PR id, head commit, diff hash, intent nonce and chain height. Validators must also keep a set of consumed intent ids, since a valid certificate is replayable by construction.

### 2.6.4 API key confidentiality

The Anthropic API authenticates with an `x-api-key` header [A1]. Redaction is byte-range based: undisclosed ranges appear redacted to the verifier, and since alpha.13 "redacted data incurs no proving overhead" [T2][T3].

The risk is over-redaction. A contributor could hide parts of the request that change its meaning, such as an extra system prompt. Validators must require that everything except the value bytes of the key header is revealed, and must parse the revealed request strictly (no duplicate headers, exact body length).

### 2.6.5 Model identity, streaming, and framing

- **Model field.** Anthropic states that each model ID is a pinned snapshot; dateless IDs from the 4.6 generation on are snapshots, while older short aliases resolve to the latest dated snapshot [A2]. Validators should pin an exact ID in the request and check the response's `model` field.
- **Fallback.** A beta `fallbacks` request parameter lets the API retry a refused request on a different model inside a single call; the documentation's example shows a response whose `model` names the fallback model rather than the requested one [A4]. Validators should reject requests that set `fallbacks`, and should require an acceptable `stop_reason`, since a classifier refusal arrives as a normal response with `stop_reason: "refusal"` [A4].
- **Self-reporting.** The `model` field is a statement by the provider. It is authenticated as coming from the provider's TLS endpoint, not independently verified.
- **Streaming.** With `stream: true` the body is a sequence of SSE events (`message_start`, content block deltas, `message_delta`, `message_stop`), interleaved with any number of `ping` events and possibly `error` events mid-stream [A3]. DOSR should use non-streaming requests.
- **HTTP framing.** The transcript commits to raw application bytes. Chunked transfer encoding was only made ergonomic in alpha.15 [T2]; the FAQ recommends `Accept-Encoding: identity` and `Connection: close` [T3].
- **TLS compatibility.** On 2026-09-29 we probed `api.anthropic.com`, `api.openai.com` and `generativelanguage.googleapis.com` with `openssl s_client -tls1_2`. All three negotiated TLS 1.2 with both `ECDHE-RSA-AES128-GCM-SHA256` and `ECDHE-ECDSA-AES128-GCM-SHA256`, the suites TLSNotary enables [M1]. This is a single-vantage measurement and providers may withdraw TLS 1.2 at any time.

## 2.7 Proof of API call for on-chain gating

Chainlink productized DECO. Its 2023 introduction stresses that "the TLS server does not have to be modified or even be aware" and describes the use of VOLE-based interactive ZK [C1]. The DECO Sandbox opened publicly on 2024-10-30; in its architecture "Chainlink Oracles run DECO Verifier to verify the received proof and create an attestation that is submitted onchain for consumption by the Smart Contract" [C2].

This is the pattern DOSR needs, and it confirms the designated-verifier point: the chain consumes an oracle's signed attestation, not the TLS proof. The consensus-layer question is which keys validators accept and under what quorum.

## 2.8 Comparison

"NP" means no figure was found in the sources fetched.

| Mechanism | Trust assumption | Who sees plaintext | Prover overhead | Verifier cost | Proof size | Unmodified HTTPS API? | Maturity |
|---|---|---|---|---|---|---|---|
| MPC-TLS + notary attestation (TLSNotary) | Notary does not collude with prover; CA PKI | Prover only; notary sees ciphertext and lengths | High: about 25 MB + 10 MB/KB sent + 40 KB/KB received; 3.6 to 14.5 s for 1 KB/2 KB [T3][T11] | Signature, Merkle and commitment checks, certificate chain | NP | Yes, TLS 1.2 with AES-128-GCM only [T4] | Alpha; no maintained notary server [T2] |
| MPC three-party handshake (DECO) | Verifier honest for integrity; none for privacy | Prover only | 2.85 s handshake + 2.52 s query (WAN); ZK 3 to 13 s [R1] | Interactive | NP | Yes (TLS 1.2 implemented; 1.3 described) | Paper; Chainlink sandbox [C2] |
| Proxy + ZK (TLSNotary proxy mode, ORIGO, Reclaim) | As above, plus verifier-to-server network path not hijacked [T12][R1] | Prover only; proxy sees ciphertext and server identity | Low: 1.0 to 1.6 s for 1 KB/2 KB [T11] | ZK verification and tag recomputation | NP | Yes, but server sees the proxy's IP | TLSNotary: alpha. Reclaim: deployed [I1] |
| Pure forwarding proxy (Luo et al.) | Honest proxy; network path; HTTP padding or a context-unforgeable AEAD (not AES-GCM) [R7] | Prover; response may be open to verifier | Minimal | Minimal | NP | Yes, with cipher restrictions | Paper (AFT 2025) |
| TEE LLM gateway (OpenGradient) | Hardware vendor, enclave isolation, correct measurements, honest image [G1][T13] | Enclave (request, response, provider key) | Near zero for the client | Attestation chain plus one RSA-PSS verification | Hashes, signature, timestamp | Yes | Open source, operated service [G1] |
| TEE oracle (Town Crier) | Intel SGX | Enclave | Low | Attestation plus signature | NP | Yes | Paper and prototype [R2] |
| **Trusted attesting proxy (DOSR checkpoint)** | Attestor fully trusted for integrity and confidentiality | Attestor (including API key) | Near zero | One signature plus Merkle proofs | Small | Yes | Prototype |
| zkML (EZKL, zkLLM) | Cryptographic soundness; prover has weights | Prover | Very high: under 15 min for 13B parameters [Z2] | Low | Under 200 kB (zkLLM) [Z2] | **No**, needs the model | Research; EZKL audited [Z1] |
| opML | One honest challenger who can re-run the model | Public | Native inference | Fraud-proof game | n/a | **No** | Research [Z3] |

## 2.9 Implications for the DOSR prototype

**What the checkpoint prototype is.** The attestor terminates the TLS connection to the provider, sees request and response in plaintext (including the API key), and signs a Merkle commitment over transcript fields so the key header can be withheld in the presentation. In the table above this is the "trusted attesting proxy" row. It should not be described as TLSNotary or zkTLS.

**Differences from MPC-TLS.**

| Property | DOSR prototype | MPC-TLS with notary |
|---|---|---|
| API key exposure | Attestor sees the key; redaction hides it only from validators | Notary never sees the key or any plaintext |
| Forgery by attestor alone | Possible: it can sign a transcript that never occurred | Also possible for a notary that colludes with the prover |
| Forgery by contributor alone | Not possible without the attestor key | Not possible |
| Provider binding | Attestor's word that it connected to the provider | Server ephemeral key and certificate commitment in the attestation, checked against a root store |
| Who connects to the provider | Attestor | Contributor |

The integrity trust is of the same kind in both designs, a signature by a witness that validators have chosen to trust [T10][T13]. The honest difference is **confidentiality**, plus the fact that MPC-TLS gives cryptographic evidence of the server identity.

**Differences from a TEE gateway.** A TEE gateway has the same data flow as the prototype (terminate TLS, see plaintext, sign hashes) but binds the signing key to a measured image through remote attestation. The prototype's attestor key is bound to nothing. Wrapping the attestor in an enclave would reach the OpenGradient trust model; it would not reach MPC-TLS confidentiality.

**What swapping in real TLSNotary requires.**

1. **A notary service.** None is maintained upstream since alpha.13. DOSR must build one on `tlsn` and `tlsn-attestation`, run by validators, with keys registered on-chain and an M-of-N acceptance rule.
2. **A Rust or WASM boundary.** The prototype is Go; the prover and the presentation verifier are Rust. `Presentation::verify` would sit behind the existing `Verifier` interface through FFI, a sidecar process, or WASM.
3. **Deterministic verification.** All validators must reach the same result, which means pinning the `tlsn` version, the root certificate store, and the certificate validation time. Validation must be evaluated at the attested connection time, not at wall-clock time, or validators will diverge when certificates expire.
4. **Request size budget.** Sent bytes dominate MPC cost. DOSR needs a hard cap on diff size for MPC mode, or must adopt proxy mode and accept its network assumption.
5. **Strict transcript policy.** Non-streaming, `Accept-Encoding: identity`, `Connection: close`, exact model ID, no `fallbacks`, full request revealed except the key value, and the verdict parsed from a structured field.
6. **Application binding.** Intent nonce, PR id, diff hash and chain height inside the revealed request body, optionally duplicated in an attestation extension.
7. **Version risk.** The library is alpha with frequent breaking changes; the certificate format must carry a version tag so that old certificates remain verifiable.

**Recommended wording for the report:** the checkpoint demonstrates the certificate format, redaction, replay protection and deterministic validator checks under a trusted-attestor assumption; replacing the attestor with MPC-TLS removes the attestor's access to plaintext and the API key, but does not remove the need to trust the notary set against collusion.

## 2.10 Could not verify

- **Byte sizes** of TLSNotary attestations and presentations: no published figure found.
- **TLSNotary bandwidth formula**: taken from the FAQ, which describes it as an expectation for a 2025 upgrade; not confirmed against alpha.15 measurements.
- **TLSNotary proxy-mode introduction post** (2026-04-22): read only through a summarizing fetch. Proxy-mode claims above rely on the docs page and the benchmark post, which were read in source form.
- **Opacity** official documentation returned HTTP 403. The description rests on an undated HackMD design note of unclear authorship; whether it reflects the deployed system is unknown.
- **zkPass** internals (MPC versus proxy modes, what nodes observe): the documentation page fetched was marked as undergoing updates and gave only high-level claims.
- **Reclaim Protocol** whitepaper was not fetched; the description relies on Reclaim's own blog post and the Luo et al. abstract.
- **Janus, ORIGO, DiStefano, Garble-then-Prove**: verified at abstract level only (ORIGO also its introduction). ORIGO's venue was seen only in a search-result listing (PoPETs 2025); the ePrint page lists it as a preprint.
- **Marlin Oyster, Atoma, "DIDO"**: not investigated; no claims made.
- **Phala and NEAR AI**: the exact TEE technology and whether closed-weight third-party models are proxied were not stated on the pages fetched.
- **OpenAI `seed` and `system_fingerprint`**: the official page returned 404 after a redirect. Only search-result snippets were seen, so no claim is made in the body.
- **"Temperature 0 is not deterministic" as an Anthropic statement**: not found in current documentation, which instead deprecates the parameter. The non-determinism claim rests on Atil et al. and on Anthropic's serving-infrastructure note.
- **Publication venues** for Town Crier and Greshake et al.: not stated on the pages fetched; cited by ePrint and arXiv identifiers only.
- **Chainlink's acquisition of DECO** and any production (non-sandbox) deployment: not confirmed.
- **Approval grinding**: no prior work found that names or analyzes this attack. Section 2.6.1 mitigations are our own design reasoning.
- **OpenGradient on-chain key registration**: not confirmed from the README.
- **Anthropic response `model` under fallback**: inferred from a documentation example, not from a normative statement.

## References

All URLs accessed 2026-09-29.

**TLSNotary**

- [T1] TLSNotary, `tlsn` repository README and `crates/tlsn/Cargo.toml` (main). https://github.com/tlsnotary/tlsn
- [T2] TLSNotary, release notes v0.1.0-alpha.4 through v0.1.0-alpha.15. https://github.com/tlsnotary/tlsn/releases
- [T3] TLSNotary, "Frequently Asked Questions". https://tlsnotary.org/docs/faq
- [T4] TLSNotary, `crates/tls-core/src/suites/mod.rs` (`ALL_CIPHER_SUITES`). https://github.com/tlsnotary/tlsn/blob/main/crates/tls-core/src/suites/mod.rs
- [T5] TLSNotary, "Handshake". https://tlsnotary.org/docs/protocol/mpc-tls/handshake
- [T6] TLSNotary, "Encryption, Decryption, and MAC Computation". https://tlsnotary.org/docs/protocol/mpc-tls/encryption
- [T7] TLSNotary, "Configuration". https://tlsnotary.org/docs/protocol/configuration
- [T8] TLSNotary, `crates/attestation/src/lib.rs`. https://github.com/tlsnotary/tlsn/blob/main/crates/attestation/src/lib.rs
- [T9] TLSNotary, `crates/core/src/connection.rs` (`ConnectionInfo`). https://github.com/tlsnotary/tlsn/blob/main/crates/core/src/connection.rs
- [T10] TLSNotary blog, "Zero-knowledge ≠ trustless: what 'publicly verifiable' means for zkTLS", 2026-06-17. https://tlsnotary.org/blog/2026/06/17/public-verifiability
- [T11] TLSNotary blog, "Proxy mode benchmarks: what the new mode actually buys you", 2026-05-10. https://tlsnotary.org/blog/2026/05/10/blog-proxy-mode
- [T12] TLSNotary, "Proxy Mode". https://tlsnotary.org/docs/protocol/proxy-mode
- [T13] TLSNotary blog, "Where does your trust live? Cryptographic soundness and the TEE trade", 2026-06-23. https://tlsnotary.org/blog/2026/06/23/where-trust-lives

**Research papers**

- [R1] F. Zhang, D. Maram, H. Malvai, S. Goldfeder, A. Juels. "DECO: Liberating Web Data Using Decentralized Oracles for TLS." ACM CCS 2020 (extended version). https://arxiv.org/abs/1909.00938
- [R2] F. Zhang, E. Cecchetti, K. Croman, A. Juels, E. Shi. "Town Crier: An Authenticated Data Feed for Smart Contracts." ePrint 2016/168. https://eprint.iacr.org/2016/168
- [R3] X. Xie, K. Yang, X. Wang, Y. Yu. "Lightweight Authentication of Web Data via Garble-Then-Prove." USENIX Security 2024; ePrint 2023/964. https://eprint.iacr.org/2023/964
- [R4] S. Celi, A. Davidson, H. Haddadi, G. Pestana, J. Rowell. "DiStefano: Decentralized Infrastructure for Sharing Trusted Encrypted Facts and Nothing More." ePrint 2023/1063. https://eprint.iacr.org/2023/1063
- [R5] J. Lauinger, J. Ernstberger, A. Finkenzeller, S. Steinhorst. "Janus: Fast Privacy-Preserving Data Provenance For TLS." PoPETs 2025; ePrint 2023/1377. https://eprint.iacr.org/2023/1377
- [R6] J. Ernstberger, J. Lauinger, Y. Wu, A. Gervais, S. Steinhorst. "ORIGO: Proving Provenance of Sensitive Data with Constant Communication." ePrint 2024/447. https://eprint.iacr.org/2024/447
- [R7] Z. Luo, Y. Jia, Y. Shen, A. Kate. "Proxying Is Enough: Security of Proxying in TLS Oracles and AEAD Context Unforgeability." AFT 2025; ePrint 2024/733. https://eprint.iacr.org/2024/733

**Industry zkTLS and oracles**

- [I1] Reclaim Protocol blog, "Proxying Is Enough". https://blog.reclaimprotocol.org/posts/proxying-is-enough
- [I2] "Opacity AVS Slashing Conditions" (HackMD note). https://hackmd.io/ZG6-EbI_QJeMBBQBv8bUkQ
- [I3] zkPass documentation, Introduction. https://docs.zkpass.org/overview/introduction
- [C1] Chainlink blog, DECO introduction, 2023-04-04. https://chain.link/blog/deco-introduction
- [C2] Chainlink blog, "Chainlink DECO Sandbox Is Now Publicly Accessible", 2024-10-30. https://chain.link/blog/deco-sandbox

**TEE gateways**

- [G1] OpenGradient, `tee-gateway` README. https://github.com/OpenGradient/tee-gateway
- [G2] Phala, Confidential AI overview. https://docs.phala.com/phala-cloud/confidential-ai/overview
- [G3] NEAR AI Cloud, Verification. https://docs.near.ai/cloud/verification/

**Verifiable ML**

- [Z1] EZKL repository README. https://github.com/zkonduit/ezkl
- [Z2] H. Sun, J. Li, H. Zhang. "zkLLM: Zero Knowledge Proofs for Large Language Models." ACM CCS 2024. https://arxiv.org/abs/2404.16109
- [Z3] K. D. Conway, C. So, X. Yu, K. Wong. "opML: Optimistic Machine Learning on Blockchain." https://arxiv.org/abs/2401.17555

**LLM behavior and provider APIs**

- [N1] B. Atil et al. "Non-Determinism of 'Deterministic' LLM Settings." https://arxiv.org/abs/2408.04667
- [P1] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, M. Fritz. "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." https://arxiv.org/abs/2302.12173
- [P2] OWASP, "LLM01:2025 Prompt Injection". https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- [A1] Anthropic, Messages API reference (create). https://platform.claude.com/docs/en/api/messages/create
- [A2] Anthropic, "Model IDs and versioning". https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions
- [A3] Anthropic, "Streaming messages". https://platform.claude.com/docs/en/build-with-claude/streaming
- [A4] Anthropic, "Refusals and fallback". https://platform.claude.com/docs/en/build-with-claude/refusals-and-fallback

**Own measurement**

- [M1] `openssl s_client -connect <host>:443 -tls1_2 -cipher <suite>` against `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, run 2026-09-29 with OpenSSL 3.0.17 from a single vantage point.
