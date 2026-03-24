# Attest Credential Standard 01 (ACS-01)

**Document identifier:** ACS-01
**Version:** 0.1.0-draft
**Date:** 2026-03-19
**Authors:** Attest Project Contributors
**Status:** Draft Standard

---

## Abstract

The Attest Credential Standard (ACS-01) defines a cryptographic credentialing
protocol for autonomous AI agent pipelines. An Attest credential is a
short-lived JSON Web Token (JWT) signed with RS256 that carries a set of
scope-limited permissions together with a SHA-256 hash of the original human
instruction that initiated the task. Credentials may be delegated to child
agents; each delegation narrows scope, cannot outlive its parent, increments a
delegation depth counter, and extends a tamper-evident chain of token
identifiers. Every lifecycle event is recorded in an append-only,
hash-chained audit log. This document specifies the credential format, issuance
rules, delegation rules, verification algorithm, revocation semantics, and
audit log structure that together constitute ACS-01.

---

## Status of This Document

This document is a **Draft Standard** of the Attest Project. It is intended for
review and implementation feedback. Sections marked MUST, MUST NOT, REQUIRED,
SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be
interpreted as described in RFC 2119 [RFC2119].

The reference implementation is the Go server located at
`github.com/attest-dev/attest/server`. In any conflict between this document
and the reference implementation, this document is normative for new
implementations; discrepancies should be reported as issues against the
specification.

---

## Table of Contents

1. Introduction
2. Terminology
3. Credential Format
4. Scope Model
5. Issuance
6. Delegation
7. Verification
8. Revocation
9. Human-in-the-Loop Approval
10. Audit Log
11. Security Considerations
12. IANA Considerations
13. References

---

## 1. Introduction

### 1.1 Problem Statement

Contemporary authorization frameworks such as OAuth 2.0 [RFC6749] and OpenID
Connect [OIDC] were designed for human-initiated, single-hop delegations: a
resource owner grants a client access on behalf of themselves. AI agent
pipelines violate this assumption in several important ways.

First, an agent pipeline may involve an arbitrary number of hops. A root agent
receives a task from a human, decomposes it, and delegates sub-tasks to child
agents, which may themselves delegate further. OAuth's two-party model has no
native representation for this; each hop requires a fresh grant cycle or an
out-of-band trust agreement.

Second, the originating human instruction — the intent — is not cryptographically
bound to any OAuth token. An agent can receive a token whose original purpose
has been transformed or corrupted by prompt injection at an intermediate step,
and the verifying party has no way to detect this.

Third, scope in OAuth is flat and is not guaranteed to narrow monotonically
through a delegation chain. A child agent can, in principle, present its parent
token to a different authorization server and request broader access. Nothing in
the wire format prevents scope creep.

Fourth, the delegation graph is not natively recorded. OAuth introspection
surfaces information about a single token; it provides no view of the full
task ancestry.

Recent IETF work — notably the WIMSE working group and the draft on AI agents
acting on behalf of users [OBO01] — acknowledges these gaps but stops short of
specifying a compact, self-contained credential format with cryptographically
enforced monotone scope reduction and intent binding.

### 1.2 What Attest Adds

ACS-01 addresses the gaps above as follows.

**Intent binding.** Every Attest credential carries `att_intent`, a
hex-encoded SHA-256 hash of the original UTF-8 instruction text. This value is
set at issuance and propagated unchanged through every delegation. A verifier
can confirm that a presented credential descends from a specific human
instruction by independently computing the hash.

**Monotone scope reduction.** At delegation time the issuer MUST verify that the
child's requested scope is a subset of the parent's scope using the `IsSubset`
algorithm defined in Section 4. Any request that fails this check MUST be
rejected. Scope therefore only ever narrows; it can never widen through
delegation.

**Depth-limited delegation.** Each credential carries `att_depth`, an integer
that starts at 0 for a root credential and increments by 1 at each delegation.
Depth is bounded above by `MaxDelegationDepth` (10). A credential whose depth
equals this limit MUST NOT be used as a parent for further delegation.

**Tamper-evident chain.** Each credential carries `att_chain`, an ordered list
of JWT IDs from the root of the delegation tree to the current token. The
verifier checks that the chain length equals `att_depth + 1` and that the final
element equals the token's own `jti`. Together these checks detect any
tampering with the ancestry record.

**Lifetime containment.** A child credential's expiry is capped at the parent's
expiry. Concretely, `exp = min(requested_exp, parent_exp)`. This ensures that
revoking a parent token effectively expires all descendants, even without an
active revocation lookup.

**Cascade revocation.** The revocation store records revoked JTIs and cascades
revocation to all descendants by inspecting the `att_chain` column in the
credential store. Revocation is permanent and takes precedence over token expiry.

**Append-only audit log.** Every issuance, delegation, verification, revocation,
and expiry event is recorded in a hash-chained log. Each entry commits to the
previous entry's hash, the event type, the JTI, and the timestamp, forming a
tamper-evident record of all credential lifecycle events within a task tree.

### 1.3 Relationship to Prior Art

ACS-01 is informed by but is not a profile of any existing specification. The
Agentic JWT (A-JWT) paper [AJWT] proposes delegation chains for AI agents but
does not specify exact claim semantics, scope subset enforcement, or audit log
structure. The IETF draft `draft-goswami-agentic-jwt-00` [AGENTJWT] covers
similar ground in the JWT format domain. The `draft-oauth-ai-agents-on-behalf-of-user-01`
[OBO01] addresses delegation in the OAuth authorization code flow context.
ACS-01 occupies a different point in the design space: it is a self-contained
signed-token format with no external authorization server required at
verification time.

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 [RFC2119].

**Issuer.**
The service that creates and signs Attest credentials. The Issuer holds an RSA
private key and is identified by a URI recorded in the `iss` JWT claim. A single
Issuer MAY serve multiple task trees.

**Root Credential.**
An Attest credential whose `att_depth` is 0 and whose `att_pid` is absent. A
root credential is issued directly by the Issuer in response to a human
principal's instruction. Its `att_chain` contains exactly one element: its own
`jti`.

**Delegated Credential.**
An Attest credential whose `att_depth` is greater than 0. A delegated credential
is derived from a parent credential and MUST have a `att_pid` set to the
parent's `jti`. Its scope MUST be a subset of the parent's scope and its expiry
MUST NOT exceed the parent's expiry.

**Task Tree.**
The complete graph of credentials that share the same `att_tid`. A task tree
has exactly one root credential; all other credentials in the tree are delegated
credentials descended from it. The task tree encodes the full delegation
history of a single human-initiated task.

**Intent Hash.**
The value of the `att_intent` claim: a lowercase hex-encoded SHA-256 digest of
the UTF-8 encoding of the original human instruction string. The intent hash is
set at root issuance and propagated unchanged to all descendants.

**Depth.**
The integer value of `att_depth`. Depth 0 identifies a root credential. Each
delegation increments depth by exactly 1. The maximum permitted depth is
`MaxDelegationDepth` (10).

**Chain.**
The ordered list of JWT IDs in `att_chain`. For a credential at depth D, the
chain contains exactly D+1 elements: the root credential's `jti` at index 0,
followed by each intermediate credential's `jti` in delegation order, with the
current credential's `jti` at the final position (index D).

**Scope Entry.**
A string of the form `resource:action` where `resource` and `action` are
non-empty strings. The wildcard character `*` MAY appear in either position to
denote "any resource" or "any action" respectively. A scope entry is the
atomic unit of permission in ACS-01.

**Revocation.**
The act of permanently invalidating a credential and all of its descendants.
A revoked credential MUST be treated as invalid regardless of its `exp` claim.
Revocation is recorded in the revocation store and is irreversible.

---

## 3. Credential Format

### 3.1 Overview

An Attest credential is a JSON Web Token [RFC7519] with:

- Header: `{ "alg": "RS256", "typ": "JWT" }`
- Payload: the claims defined in Sections 3.2 and 3.3
- Signature: RS256 over the ASCII representation of the header and payload

All implementations MUST use RS256 (RSASSA-PKCS1-v1_5 using SHA-256) as the
signing algorithm. No other signing algorithm is permitted under ACS-01.

### 3.2 Standard JWT Claims

The following standard JWT claims are used. All are REQUIRED unless noted.

| Claim | Type   | Required | Description |
|-------|--------|----------|-------------|
| `iss` | string | REQUIRED | Issuer URI. Identifies the Attest Issuer service. |
| `sub` | string | REQUIRED | Subject. MUST be of the form `agent:{agent_id}` where `agent_id` is the identifier of the agent holding this credential. |
| `iat` | NumericDate | REQUIRED | Issued-at time (Unix epoch seconds, UTC). |
| `exp` | NumericDate | REQUIRED | Expiry time (Unix epoch seconds, UTC). The credential MUST be rejected if the current time is at or after this value (subject to clock-skew allowance; see Section 11.4). |
| `jti` | string | REQUIRED | JWT ID. A UUID v4 string that uniquely identifies this credential within the Issuer's namespace. Used as the revocation key and as the chain anchor. |

The `sub` claim MUST match the pattern `^agent:[A-Za-z0-9_\-]+$`. Implementations
MUST reject credentials whose `sub` does not begin with the literal prefix
`agent:`.

### 3.3 Attest Extension Claims

All Attest-specific claims are prefixed with `att_`. Implementations MUST
ignore unknown `att_*` claims to allow forward compatibility.

| Claim | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `att_tid` | string (UUID v4) | REQUIRED | Task tree identifier. Shared across every credential in the same delegation chain. Set at root issuance; propagated unchanged to all descendants. | MUST be a UUID v4. MUST NOT change through delegation. |
| `att_pid` | string (UUID v4) | CONDITIONAL | Parent credential identifier. The `jti` of the credential from which this one was delegated. | MUST be present for delegated credentials (`att_depth` > 0). MUST be absent for root credentials (`att_depth` == 0). |
| `att_depth` | integer | REQUIRED | Delegation depth. 0 for a root credential; incremented by 1 for each delegation. | MUST be a non-negative integer. MUST NOT exceed `MaxDelegationDepth` (10). |
| `att_scope` | array of strings | REQUIRED | Permission set. Each element is a scope entry of the form `resource:action`. | MUST contain at least one element. Each element MUST be parseable as a scope entry. MUST be normalised (see Section 4.3). |
| `att_intent` | string (hex) | REQUIRED | Intent hash. SHA-256 of the original human instruction, hex-encoded (64 lowercase hex characters). | MUST be exactly 64 lowercase hexadecimal characters. MUST be propagated unchanged through delegation. |
| `att_chain` | array of strings | REQUIRED | Delegation ancestry. Ordered list of `jti` values from the root credential to this credential. | Length MUST equal `att_depth + 1`. Final element MUST equal this credential's `jti`. |
| `att_uid` | string | REQUIRED | User identifier. The identifier of the human principal who initiated the task. | MUST be propagated unchanged through delegation. |
| `att_hitl_req` | string (UUID v4) | OPTIONAL | Approval Request identifier. Present if the token was granted via an explicit HITL approval. | MUST be a UUID v4 if present. |
| `att_hitl_uid` | string | OPTIONAL | Identifier of the human who approved the HITL challenge. | MUST be present if `att_hitl_req` is present. |
| `att_hitl_iss` | string | OPTIONAL | Human approval issuer. Delineates the Identity Provider (IdP) source. | Used to map external OIDC approvals back to the verifying authority. |
| `att_idp_iss` | string | OPTIONAL | The IdP Issuer URI that authenticated the initial human user. | Copied from the root OIDC session. |
| `att_idp_sub` | string | OPTIONAL | The IdP Subject (human user ID) mapped during the root session. | Copied from the root OIDC session. |
| `att_ack` | string | OPTIONAL | Agent checksum validation digest. Used to prevent agent substitution via binary hashing. | |

### 3.4 Concrete Examples

#### 3.4.1 Root Credential Payload

The following is a decoded JWT payload for a root credential. The human
instruction was `"Summarise the inbox and draft three reply emails."`.

```json
{
  "iss": "https://attest.example.com",
  "sub": "agent:inbox-agent-v2",
  "iat": 1742386800,
  "exp": 1742473200,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "att_tid": "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
  "att_depth": 0,
  "att_scope": [
    "email:read",
    "email:draft"
  ],
  "att_intent": "3b4c2a1f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1",
  "att_chain": [
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  ],
  "att_uid": "user:alice"
}
```

Note that `att_pid` is absent because this is a root credential (`att_depth`
is 0). The `att_chain` contains exactly one element — the credential's own
`jti`.

#### 3.4.2 Delegated Credential Payload

The following is a decoded JWT payload for a credential delegated from the root
credential above. The child agent is granted only `email:read` (a subset of the
parent's `["email:read", "email:draft"]`).

```json
{
  "iss": "https://attest.example.com",
  "sub": "agent:summariser-agent-v1",
  "iat": 1742387100,
  "exp": 1742473200,
  "jti": "c3d4e5f6-a7b8-9012-cdef-012345678901",
  "att_tid": "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
  "att_pid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "att_depth": 1,
  "att_scope": [
    "email:read"
  ],
  "att_intent": "3b4c2a1f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1",
  "att_chain": [
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "c3d4e5f6-a7b8-9012-cdef-012345678901"
  ],
  "att_uid": "user:alice"
}
```

Observe that:
- `att_pid` is set to the parent's `jti`.
- `att_depth` has incremented from 0 to 1.
- `att_scope` is `["email:read"]`, a proper subset of the parent's scope.
- `att_intent`, `att_tid`, and `att_uid` are unchanged from the parent.
- `att_chain` extends the parent's chain by appending this credential's `jti`.
- `exp` equals the parent's `exp` because no earlier TTL was requested.

---

## 4. Scope Model

### 4.1 Scope Entry Format

A scope entry is a string conforming to the grammar:

```
scope-entry = resource ":" action
resource    = 1*( ALPHA / DIGIT / "_" / "-" / "*" )
action      = 1*( ALPHA / DIGIT / "_" / "-" / "*" )
```

Both `resource` and `action` MUST be non-empty. A scope entry that does not
contain exactly one colon character, or whose `resource` or `action` component
is empty, is invalid. Implementations MUST reject invalid scope entries at all
stages: issuance, delegation, and verification.

### 4.2 Wildcard Rules

The wildcard character `*` MAY appear as the entirety of either the `resource`
or `action` component (or both). A wildcard component matches any non-empty
string in the corresponding position. The following coverage rules apply to a
parent entry P and a child entry C:

- P covers C if P.resource equals `*` OR P.resource equals C.resource, AND
- P covers C if P.action equals `*` OR P.action equals C.action.

Consequently:
- `*:*` covers every valid scope entry.
- `email:*` covers `email:read`, `email:draft`, `email:delete`, and so on.
- `*:read` covers `email:read`, `calendar:read`, `files:read`, and so on.
- `email:read` covers only the literal entry `email:read`.

Wildcards in the child position have no special meaning with respect to
coverage. If the child scope contains `email:*`, this is a single scope entry
that a parent entry covers only if the parent itself also contains a wildcard
in the action position (e.g. `email:*` or `*:*`). A parent entry of
`email:read` does NOT cover a child entry of `email:*`.

### 4.3 NormaliseScope

Before storing scope in any credential or comparing scopes, implementations
MUST apply the NormaliseScope procedure:

1. Trim leading and trailing whitespace from each entry.
2. Remove any empty entries that result from trimming.
3. Remove duplicate entries, preserving the first occurrence.
4. Return the resulting list in the order entries were first seen (insertion order).

NormaliseScope does not sort entries. The output is deterministic given a fixed
input ordering. Implementations MUST apply NormaliseScope to the scope provided
at issuance and at delegation before embedding scope in the credential.

### 4.4 IsSubset Algorithm

The delegation rule requires that the child scope be a subset of the parent
scope under the wildcard coverage semantics defined above. The following
pseudocode defines the normative algorithm:

```
function IsSubset(parentScope, childScope):
    for each entry CE in childScope:
        childEntry = ParseScope(CE)
        if childEntry is invalid:
            return false
        covered = false
        for each entry PE in parentScope:
            parentEntry = ParseScope(PE)
            if parentEntry is invalid:
                continue
            if EntryCovers(parentEntry, childEntry):
                covered = true
                break
        if not covered:
            return false
    return true

function EntryCovers(parent, child):
    resourceOK = (parent.Resource == "*") OR (parent.Resource == child.Resource)
    actionOK   = (parent.Action  == "*") OR (parent.Action  == child.Action)
    return resourceOK AND actionOK
```

IsSubset returns `true` if every entry in `childScope` is covered by at least
one entry in `parentScope`. IsSubset returns `false` if any child entry is
invalid or uncovered. An empty `childScope` is vacuously true (every entry in
the empty set is covered), but implementations MUST reject a credential with an
empty scope at issuance and at delegation (see Sections 5.2 and 6.2).

---

## 5. Issuance

### 5.1 Overview

Issuance creates a root credential (depth 0) that anchors a new task tree. The
Issuer MUST perform all validation checks in Section 5.2 before constructing
the credential. The Issuer MUST sign the credential with its RSA private key
using RS256.

### 5.2 Input Validation

The Issuer MUST reject the issuance request if any of the following conditions
hold:

1. `agent_id` is absent or empty.
2. `user_id` is absent or empty.
3. `scope` is absent or contains no entries.
4. Any entry in `scope` is not parseable as a valid scope entry.
5. `instruction` is absent or empty.

### 5.3 Intent Hash Computation

The intent hash is computed as:

```
att_intent = lowercase-hex( SHA-256( UTF-8-encode( instruction ) ) )
```

The `instruction` string MUST be encoded as UTF-8 before hashing. The resulting
32-byte SHA-256 digest MUST be encoded as 64 lowercase hexadecimal characters.
No canonicalisation (whitespace normalisation, newline stripping, etc.) is
applied to the instruction before hashing; the raw UTF-8 bytes are hashed
as-is. Implementations MUST use exactly this procedure to ensure that
independent verifiers can reproduce the intent hash from the original
instruction text.

### 5.4 Identifier Generation

The Issuer MUST generate two UUID v4 values at issuance:

- `jti`: the unique identifier for this credential. Stored in the JWT `jti`
  claim and used as the revocation key.
- `att_tid`: the task tree identifier. Shared by all credentials in this task
  tree. Propagated unchanged to all delegated credentials.

Both values MUST be generated using a cryptographically secure random source.
The reference implementation uses the `github.com/google/uuid` library.

### 5.5 TTL and Expiry

The requested TTL (in seconds) is subject to the following rules:

1. If `ttl_seconds` is zero, the TTL defaults to `DefaultTTLSeconds` (3600 seconds, i.e. 1 hour).
2. If `ttl_seconds` is negative, the issuance MUST be rejected.
3. If `ttl_seconds` is positive but exceeds `MaxTTLSeconds`, the TTL is capped
   at `MaxTTLSeconds` (86400 seconds, i.e. 24 hours).
4. The credential's `exp` claim is set to `iat + ttl_seconds` (after applying
   the rules above).

Implementations MUST NOT issue credentials with `exp - iat` greater than
86400 seconds.

### 5.6 Root Credential Construction

After validation, the root credential is constructed with the following field
assignments:

| Field | Value |
|-------|-------|
| `iss` | Issuer URI |
| `sub` | `"agent:" + agent_id` |
| `iat` | Current UTC time as NumericDate |
| `exp` | `iat + ttl` as NumericDate |
| `jti` | Freshly generated UUID v4 |
| `att_tid` | Freshly generated UUID v4 |
| `att_pid` | Absent (omitted from JSON) |
| `att_depth` | `0` |
| `att_scope` | `NormaliseScope(scope)` |
| `att_intent` | `hex(SHA-256(UTF-8(instruction)))` |
| `att_chain` | `[ jti ]` |
| `att_uid` | `user_id` |

The Issuer MUST record the credential in the credential store before returning
the signed token to the caller.

---

## 6. Delegation

### 6.1 Overview

Delegation creates a child credential derived from an existing parent
credential. The result is a credential at `att_depth + 1` with a scope that is
a subset of the parent's scope and an expiry that is no later than the parent's
expiry. The Issuer MUST perform the validation steps in Sections 6.2 and 6.3
before constructing the child credential.

### 6.2 Input Validation

The Issuer MUST reject a delegation request if any of the following conditions
hold:

1. `parent_token` is absent or empty.
2. `child_agent` is absent or empty.
3. `child_scope` is absent or contains no entries.

### 6.3 Parent Token Verification

Before processing a delegation request, the Issuer MUST:

1. Verify the RS256 signature of the parent token against the Issuer's public
   key. The parent token MUST be rejected if the signature does not verify.
2. Verify that the parent token has not expired (`exp > now`). The parent token
   MUST be rejected if it is expired.
3. Verify that the signing algorithm in the token header is `RS256`. Any other
   algorithm identifier MUST cause rejection.

Note that at delegation time, the parent token is NOT checked against the
revocation store by the Issuer's Delegate function. Callers that wish to prevent
delegation from revoked credentials SHOULD perform a revocation check before
invoking Delegate. The normative revocation check during credential presentation
is defined in Section 7.

### 6.4 Scope Subset Enforcement

The Issuer MUST apply NormaliseScope to the requested `child_scope`. The Issuer
MUST then apply IsSubset(parentScope, childScope). If IsSubset returns `false`,
the delegation request MUST be rejected with an error indicating that the child
scope is not a subset of the parent scope.

### 6.5 Depth Limit

The Issuer MUST check that `parent.att_depth < MaxDelegationDepth` (10). If the
parent's depth equals or exceeds `MaxDelegationDepth`, the delegation MUST be
rejected. Implementing this check prevents unbounded delegation chains.

### 6.6 Expiry Computation

The child credential's expiry is computed as:

```
parent_exp = parent.exp

if ttl_seconds > 0:
    requested_exp = now + ttl_seconds
    child_exp = min(requested_exp, parent_exp)
else:
    default_exp = now + DefaultTTLSeconds
    child_exp = min(default_exp, parent_exp)
```

If `ttl_seconds` is zero or omitted, the child credential's expiry defaults to
`min(now + DefaultTTLSeconds, parent.exp)`. The child credential's expiry MUST
NOT exceed the parent credential's expiry under any circumstances.

### 6.7 Delegated Credential Construction

After all validation steps pass, the delegated credential is constructed with
the following field assignments:

| Field | Value |
|-------|-------|
| `iss` | Issuer URI |
| `sub` | `"agent:" + child_agent` |
| `iat` | Current UTC time as NumericDate |
| `exp` | `min(now + ttl_seconds, parent.exp)` |
| `jti` | Freshly generated UUID v4 |
| `att_tid` | `parent.att_tid` (propagated unchanged) |
| `att_pid` | `parent.jti` |
| `att_depth` | `parent.att_depth + 1` |
| `att_scope` | `NormaliseScope(child_scope)` |
| `att_intent` | `parent.att_intent` (propagated unchanged) |
| `att_chain` | `parent.att_chain + [ jti ]` (parent chain with new jti appended) |
| `att_uid` | `parent.att_uid` (propagated unchanged) |

The Issuer MUST record the delegated credential in the credential store before
returning the signed token to the caller.

---

## 7. Verification

### 7.1 Overview

Verification determines whether a presented Attest credential is currently
valid. A credential is valid if and only if all of the following conditions are
satisfied:

1. The RS256 signature verifies against the Issuer's public key.
2. The current time is before `exp` (subject to clock-skew allowance).
3. The length of `att_chain` equals `att_depth + 1`.
4. The final element of `att_chain` equals `jti`.
5. The `jti` is not present in the revocation store.

Failure of any condition MUST cause the verification to return invalid. The
verifier SHOULD surface a descriptive reason for each failure.

### 7.2 Verification Algorithm

The normative verification algorithm is:

```
function Verify(tokenString, issuerPublicKey, revocationStore):

    // Step 1: Signature and expiry
    claims, err = RS256Parse(tokenString, issuerPublicKey)
    if err is not nil:
        return invalid("signature verification failed: " + err)

    // Step 2: Chain length invariant
    expectedLen = claims.att_depth + 1
    if len(claims.att_chain) != expectedLen:
        return invalid("chain length " + len(claims.att_chain)
                       + " does not match depth " + claims.att_depth
                       + " (expected " + expectedLen + ")")

    // Step 3: Chain tail invariant
    if len(claims.att_chain) > 0:
        tail = claims.att_chain[len(claims.att_chain) - 1]
        if tail != claims.jti:
            return invalid("chain tail does not match jti")

    // Step 4: Revocation check
    if revocationStore.IsRevoked(claims.jti):
        return invalid("credential has been revoked")

    return valid(claims)
```

Implementations MUST perform the signature check (Step 1) before the structural
checks (Steps 2 and 3) to avoid processing structurally well-formed but
cryptographically invalid tokens. Implementations MUST perform the revocation
check (Step 4) on every verification call; the result MUST NOT be cached
locally unless the cache TTL is shorter than the credential's remaining
lifetime.

### 7.3 Warnings vs. Hard Failures

In the reference implementation, chain length and chain tail inconsistencies are
surfaced as warnings that cause the credential to be reported as invalid. This
is equivalent to a hard failure from the caller's perspective: a credential
accompanied by any warnings MUST NOT be honoured. The warning mechanism exists
to allow callers to distinguish between cryptographic failures (which may
indicate active attack) and structural inconsistencies (which may indicate
implementation bugs).

---

## 8. Revocation

### 8.1 Semantics

Revocation permanently invalidates a credential identified by its `jti`. Once
revoked, a credential MUST be treated as invalid regardless of its `exp` claim.
The revocation store is the authoritative source of truth; a non-expired
credential that appears in the revocation store MUST be rejected at verification
time.

Revocation is irreversible. There is no un-revoke operation.

### 8.2 Cascade Semantics

Revoking a credential with `jti` X automatically revokes every credential in
the credential store whose `att_chain` contains X. This is the cascade rule.

The cascade rule is justified by the chain invariant: every credential whose
chain contains X is either X itself or a descendant of X in the task tree. A
descendant MUST NOT remain valid after its ancestor has been revoked, because
the ancestor's revocation reflects a decision that the associated task or scope
grant is no longer authorised.

Formally:

```
Revoke(X):
    targets = { jti | jti == X OR X ∈ credentials[jti].att_chain }
    for each T in targets:
        revocations.insert(T, now, revokedBy)   // idempotent
```

The implementation queries the credential store using the GIN-indexed `chain`
column to efficiently find all descendants:

```sql
SELECT jti FROM credentials
WHERE jti = $1 OR chain @> ARRAY[$1]::text[]
```

Cascade revocation is performed atomically within a single database transaction.
If the transaction fails, no revocations are recorded.

### 8.3 Revocation Store

The revocation store records:

| Field | Type | Description |
|-------|------|-------------|
| `jti` | text (primary key) | The revoked credential identifier |
| `revoked_at` | timestamptz | UTC timestamp of revocation |
| `revoked_by` | text | Agent or user ID that triggered the revocation |

Duplicate insert attempts (revoking an already-revoked JTI) MUST be treated as
a no-op (idempotent). The revocation store MUST be consulted on every
verification call.

### 8.4 Lifetime Interaction

A credential that has expired (`now >= exp`) is invalid regardless of the
revocation store. A credential that has been revoked is invalid regardless of
whether it has expired. These are independent failure conditions. Implementors
SHOULD maintain the revocation store even after credential expiry to allow
forensic queries.

---

## 9. Human-in-the-Loop Approval

### 9.1 Overview

Certain delegations require explicit human approval before being granted — for
example, when an agent requests access to a high-risk scope such as
`finance:transfer`. ACS-01 defines an approval protocol that makes the human
decision a cryptographic event embedded in the resulting credential.

### 9.2 Approval Lifecycle

The HITL approval flow consists of four phases:

1. **Request.** The agent (or its SDK) sends an approval request to the Issuer
   containing the `parent_token`, the requested `child_scope`, an `intent`
   description, and the `agent_id`. The Issuer creates a pending approval
   record and returns a `challenge_id`.

2. **Poll.** The agent polls the Issuer for the approval status using the
   `challenge_id`. The status is one of: `pending`, `approved`, `rejected`,
   or `expired`.

3. **Grant or Deny.** A human reviews the request via a dashboard or
   integration (e.g. Slack). To grant, the human authenticates via an OIDC
   Identity Provider and the Issuer verifies the `id_token`. The Issuer
   records the human's identity (`att_hitl_uid`, `att_hitl_iss`) and marks
   the approval as granted. To deny, no identity verification is required.

4. **Credential Issuance.** Upon grant, the Issuer delegates a new credential
   from the parent token with the approved scope. The resulting credential
   carries `att_hitl_req` (the challenge ID), `att_hitl_uid` (the approver's
   IdP subject), and `att_hitl_iss` (the approver's IdP issuer). These claims
   propagate through subsequent delegations, making the human approval
   verifiable at any point downstream.

### 9.3 Approval Expiry

Pending approvals MUST expire after a bounded time window. The reference
implementation uses a 15-minute TTL. Implementations MUST NOT allow approvals
to remain pending indefinitely. An expired approval MUST be treated identically
to a rejection.

### 9.4 Parent Token Verification at Grant Time

When an approval is granted, the Issuer MUST re-verify the parent token before
issuing the delegated credential. If the parent token has expired or been
revoked while the approval was pending, the Issuer MUST reject the grant and
mark the approval as rejected with a system reason (e.g. `system:parent_expired`).

### 9.5 HITL Claims Propagation

The HITL claims (`att_hitl_req`, `att_hitl_uid`, `att_hitl_iss`) from the
most recent human approval are propagated to all subsequent delegations in the
chain. If a credential already carries HITL claims from a parent and a new HITL
approval occurs at a deeper delegation, the new HITL claims replace the
inherited ones in the child credential.

### 9.6 Multi-Tenant Isolation

Approval requests are scoped to the authenticated organisation. An approval
created by org A MUST NOT be resolvable by org B. The `Resolve` operation
MUST validate org ownership before granting or denying.

---

## 10. Audit Log

### 10.1 Structure

The audit log is an append-only, hash-chained record of credential lifecycle
events. Each entry in the log commits to the previous entry's hash, making the
log tamper-evident: any modification to a historical entry invalidates all
subsequent hashes.

The audit log is partitioned by `att_tid`. Each task tree has its own
independent hash chain. The first event recorded for a task tree uses a genesis
hash of 64 ASCII zero characters as the previous hash value.

### 10.2 Entry Hash Computation

The hash of each log entry is computed as:

```
entry_hash = lowercase-hex( SHA-256(
    prev_hash
    || event_type
    || jti
    || created_at_rfc3339nano
) )
```

where `||` denotes string concatenation. All inputs are treated as UTF-8
strings. `created_at_rfc3339nano` is the creation timestamp formatted using
RFC 3339 with nanosecond precision (e.g.
`"2026-03-19T12:34:56.789012345Z"`).

The genesis hash (previous hash of the first entry for a given `att_tid`) is:

```
"0000000000000000000000000000000000000000000000000000000000000000"
```

(64 ASCII zero characters, representing the hex encoding of 32 zero bytes.)

### 10.3 Event Types

The following event types are defined. Implementations MUST record audit events
for all lifecycle operations.

| Event Type | Trigger |
|------------|---------|
| `issued` | A root credential has been successfully issued. |
| `delegated` | A delegated credential has been successfully issued. |
| `verified` | A credential has been presented and successfully verified. |
| `revoked` | A credential has been revoked (the target credential; one event per cascade target). |
| `expired` | A credential has reached its `exp` time (MAY be recorded by background processes). |
| `hitl_granted` | A human approved a high-risk delegation request via an external challenge. |
| `action` | An agent executed a registered action. |
| `lifecycle` | An agent transitioned between lifecycle states (started, completed, failed). |

### 10.4 Audit Entry Fields

Each audit log entry records:

| Field | Type | Description |
|-------|------|-------------|
| `id` | bigserial | Monotonically increasing database-assigned row ID |
| `prev_hash` | text | The `entry_hash` of the most recent prior entry for the same `att_tid`, or the genesis hash |
| `entry_hash` | text | SHA-256 of the concatenated fields (see Section 10.2) |
| `event_type` | text | One of the event types defined in Section 10.3 |
| `jti` | text | The JWT ID of the credential involved in this event |
| `org_id` | text | The tenant identifier bounds for the corresponding task tree |
| `att_tid` | text | Task tree identifier |
| `att_uid` | text | Human principal identifier |
| `agent_id` | text | Agent identifier |
| `scope` | jsonb | The scope array at the time of the event |
| `meta` | jsonb | Optional key-value metadata (implementation-defined) |
| `idp_issuer` | text | The IdP issuer URI from the root credential's OIDC session (OPTIONAL) |
| `idp_subject` | text | The IdP subject from the root credential's OIDC session (OPTIONAL) |
| `hitl_req` | text | The approval challenge ID, if the event relates to a HITL grant (OPTIONAL) |
| `hitl_issuer` | text | The IdP issuer of the human who approved a HITL challenge (OPTIONAL) |
| `hitl_subject` | text | The IdP subject of the human who approved a HITL challenge (OPTIONAL) |
| `created_at` | timestamptz | UTC timestamp of this entry's creation |

### 10.5 Append-Only Enforcement

The credential store MUST enforce append-only semantics on the audit log. In the
reference implementation, this is achieved at the database level by rules that
replace UPDATE and DELETE operations on the `audit_log` table with no-ops:

```sql
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;
```

Implementations using other storage backends MUST enforce equivalent append-only
guarantees through access controls, write-once storage, or other appropriate
mechanisms.

### 10.6 Log Verification

To verify the integrity of the audit log for a given `att_tid`, a verifier
MUST:

1. Retrieve all entries for the `att_tid` in ascending `id` order.
2. For each entry starting at the second, verify that `entry.prev_hash` equals
   the `entry_hash` of the preceding entry.
3. Recompute `entry_hash` from the raw fields and verify it matches the stored
   value.

Any discrepancy indicates tampering with or corruption of the audit log.

---

## 11. Security Considerations

### 11.1 Prompt Injection

Attest credentials bind to the intent hash of the original instruction, but
they do not prevent a legitimate credential from being used by a compromised
agent. If an intermediate agent in the task tree is subject to a prompt
injection attack, it may perform actions that are within the bounds of its
granted scope but contrary to the human principal's actual intent.

Attest mitigates this risk indirectly: the narrow, monotone-reducing scope
model limits the blast radius of a compromised agent to the permissions
explicitly granted to it. The intent hash enables post-hoc detection of
misuse when compared against the known original instruction. However, these
are detective and limiting controls, not preventive ones.

The `att_ack` claim (Section 3.3) carries a checksum or attestation of the
agent binary or model that holds the credential. Verifiers that receive an
expected checksum out-of-band can compare it against `att_ack` to confirm that
the credential is being presented by the specific agent software that was
originally delegated to, providing a preventive control against agent
substitution attacks.

### 11.2 Replay Attacks

Attest credentials carry a unique `jti` that MUST be recorded in the
revocation store at issuance. Verifiers MUST check the revocation store on
every verification call. Together, the `jti` uniqueness and revocation store
check mitigate replay attacks: a credential that has been revoked after use
cannot be replayed, and the `exp` claim bounds the replay window for
credentials that have not been explicitly revoked.

Verifiers SHOULD also maintain a short-term cache of recently seen `jti`
values to detect same-window replay attempts without incurring a revocation
store round-trip on every call. Any such cache MUST have a TTL shorter than
the minimum expected credential lifetime.

### 11.3 Scope Creep

Scope creep — an agent obtaining permissions broader than those granted by its
task — is prevented by the IsSubset enforcement at delegation time (Section 6.4).
Because the Issuer enforces this check before signing, a child credential with
a broader scope than its parent is not producible by any party that does not
have access to the Issuer's private key.

Implementations MUST verify the scope of presented credentials at the resource
level: a resource server MUST check that the presented credential's `att_scope`
includes an entry that covers the requested operation before granting access.

### 11.4 Clock Skew

Credential expiry is checked against the verifier's local clock. In distributed
systems, clock skew between the Issuer and verifier may cause a credential to
appear expired at the verifier before the Issuer considers it expired.
Implementations SHOULD allow a clock-skew leeway of up to 60 seconds when
evaluating the `exp` claim. Implementations MUST NOT allow a leeway of more
than 300 seconds. Implementations SHOULD log a warning when a credential is
accepted within the leeway window.

### 11.5 Key Management

The Issuer's RSA private key is the root of trust for all Attest credentials.
Compromise of the private key allows an attacker to forge credentials for any
agent with any scope. Key management controls are outside the scope of ACS-01,
but implementations SHOULD follow industry best practices including hardware
security modules for key storage, short key rotation periods, and strict access
controls on key material.

The RSA public key MUST be distributed to verifiers via an out-of-band mechanism
(e.g. a well-known JWKS endpoint). ACS-01 does not define a key discovery
protocol.

### 11.6 Credential Store Integrity

The revocation store and credential store are security-critical components.
An attacker who can delete entries from the revocation store can un-revoke
credentials. An attacker who can modify credential chain columns can break the
cascade revocation semantics. Implementations MUST apply access controls that
prevent unauthorised modification of these stores.

### 11.7 Audit Log Integrity

The hash-chaining of the audit log provides tamper-evidence but not
tamper-prevention. An attacker with write access to the audit log database can
rewrite all hashes to form a valid chain over falsified entries. The audit log
SHOULD be replicated to a write-once store (e.g. object storage with object
lock) or a transparency log to provide stronger integrity guarantees.

---

## 12. IANA Considerations

This specification defines the following JWT claim names for registration in
the IANA "JSON Web Token Claims" registry established by RFC 7519. All claims
use the `att_` prefix to identify them as belonging to the Attest Credential
Standard namespace.

| Claim Name | Claim Description | Change Controller | Reference |
|------------|-------------------|-------------------|-----------|
| `att_tid` | Attest task tree identifier | Attest Project | This document, Section 3.3 |
| `att_pid` | Attest parent credential identifier | Attest Project | This document, Section 3.3 |
| `att_depth` | Attest delegation depth | Attest Project | This document, Section 3.3 |
| `att_scope` | Attest permission scope | Attest Project | This document, Section 3.3 |
| `att_intent` | Attest intent hash | Attest Project | This document, Section 3.3 |
| `att_chain` | Attest delegation chain | Attest Project | This document, Section 3.3 |
| `att_uid` | Attest originating user identifier | Attest Project | This document, Section 3.3 |
| `att_hitl_req` | Attest HITL request ID | Attest Project | This document, Section 3.3 |
| `att_hitl_uid` | Attest HITL approving user | Attest Project | This document, Section 3.3 |
| `att_hitl_iss` | Attest HITL issuer authority | Attest Project | This document, Section 3.3 |
| `att_idp_iss` | Attest IdP issuer | Attest Project | This document, Section 3.3 |
| `att_idp_sub` | Attest IdP subject | Attest Project | This document, Section 3.3 |
| `att_ack` | Attest agent checksum digest | Attest Project | This document, Section 3.3 |

---

## 13. References

### 13.1 Normative References

**[RFC2119]**
Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119, March 1997.
<https://www.rfc-editor.org/rfc/rfc2119>

**[RFC7519]**
Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)",
RFC 7519, May 2015.
<https://www.rfc-editor.org/rfc/rfc7519>

**[RFC7518]**
Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, May 2015.
<https://www.rfc-editor.org/rfc/rfc7518>

**[RFC6749]**
Hardt, D., Ed., "The OAuth 2.0 Authorization Framework",
RFC 6749, October 2012.
<https://www.rfc-editor.org/rfc/rfc6749>

**[RFC4122]**
Leach, P., Mealling, M., and R. Salz, "A Universally Unique IDentifier (UUID)
URN Namespace", RFC 4122, July 2005.
<https://www.rfc-editor.org/rfc/rfc4122>

### 13.2 Informative References

**[OIDC]**
Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., and C. Mortimore,
"OpenID Connect Core 1.0", November 2014.
<https://openid.net/specs/openid-connect-core-1_0.html>

**[AGENTJWT]**
Goswami, D., et al., "Agentic JWT: Secure Delegation Protocol for AI Agent
Pipelines", Internet-Draft, draft-goswami-agentic-jwt-00, 2025.
<https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/>

**[AJWT]**
Goswami, D., et al., "A-JWT: A Secure Delegation Protocol for Autonomous AI
Agents", arXiv:2509.13597, September 2025.
<https://arxiv.org/abs/2509.13597>

**[OBO01]**
Internet-Draft, "OAuth 2.0 for AI Agents Acting on Behalf of Users",
draft-oauth-ai-agents-on-behalf-of-user-01, 2025.
<https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/>

**[WIMSE]**
IETF Workload Identity in Multi System Environments (WIMSE) Working Group.
<https://datatracker.ietf.org/wg/wimse/about/>

---

## Appendix A. Summary of Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MaxDelegationDepth` | 10 | Maximum permitted value of `att_depth` |
| `DefaultTTLSeconds` | 3600 | Fallback credential lifetime if TTL is omitted (1 hour) |
| `MaxTTLSeconds` | 86400 | Maximum permitted credential lifetime in seconds |
| Genesis hash | 64 × `"0"` | Previous hash value for the first audit entry of a task tree |
| Clock skew leeway (SHOULD) | 60 seconds | Recommended allowance for clock skew at expiry check |
| Clock skew leeway (MUST NOT exceed) | 300 seconds | Absolute maximum allowance for clock skew at expiry check |

---

## Appendix B. Data Model

The following SQL schema is provided for reference. It is normative for the
reference implementation but informative for alternative implementations, which
MAY use any storage backend that satisfies the semantic requirements of this
specification.

```sql
-- credentials: stores structured claims for revocation cascade queries
CREATE TABLE IF NOT EXISTS credentials (
    jti         TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL,
    att_tid     TEXT        NOT NULL,
    att_pid     TEXT,                        -- parent jti; NULL for root
    att_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    depth       INTEGER     NOT NULL DEFAULT 0,
    scope       TEXT[]      NOT NULL,
    chain       TEXT[]      NOT NULL,        -- ordered ancestor jti list
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

-- GIN index enables fast ancestor lookup: chain @> ARRAY['<jti>']
CREATE INDEX IF NOT EXISTS idx_credentials_chain ON credentials USING GIN (chain);

-- revocations: append-only set of revoked JTIs
CREATE TABLE IF NOT EXISTS revocations (
    jti         TEXT        PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT        NOT NULL
);

-- audit_log: append-only, hash-chained event log
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    org_id      TEXT        NOT NULL,
    prev_hash   TEXT        NOT NULL,
    entry_hash  TEXT        NOT NULL,
    event_type  TEXT        NOT NULL,
    jti         TEXT        NOT NULL,
    att_tid     TEXT        NOT NULL,
    att_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    scope       JSONB       NOT NULL DEFAULT '[]',
    meta        JSONB,
    idp_issuer  TEXT,                        -- IdP issuer from root credential
    idp_subject TEXT,                        -- IdP subject from root credential
    hitl_req    TEXT,                        -- approval challenge ID
    hitl_issuer TEXT,                        -- IdP issuer of the approving human
    hitl_subject TEXT,                       -- IdP subject of the approving human
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent UPDATE and DELETE on audit_log to keep it append-only.
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;

-- approvals: short-lived, stateful tracking for HITL workflows
CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT        PRIMARY KEY,
    org_id          TEXT        NOT NULL,
    agent_id        TEXT        NOT NULL,
    att_tid         TEXT        NOT NULL,
    parent_token    TEXT        NOT NULL,    -- full parent JWT for re-verification at grant time
    intent          TEXT        NOT NULL,
    requested_scope TEXT[]      NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending',
    approved_by     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);
```

---

*End of ACS-01*
