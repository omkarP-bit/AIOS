package plan

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"aios/internal/canonical"
	"aios/internal/model"
)

// ApprovalError is a refused token. The reason is safe to log.
type ApprovalError string

func (e ApprovalError) Error() string { return string(e) }

// Token is a signed operator approval. The signature covers every other field.
type Token struct {
	TokenVersion int             `json:"token_version"`
	PlanID       string          `json:"plan_id"`
	PlanHash     string          `json:"plan_hash"`
	ApprovedBy   string          `json:"approved_by"`
	ApprovedAt   model.Timestamp `json:"approved_at"`
	ExpiresAt    model.Timestamp `json:"expires_at"`
	Nonce        string          `json:"nonce"`
	ScopeDigest  string          `json:"scope_digest"`
	Signature    string          `json:"signature"`
}

// Grant is a verified token bound to one plan.
type Grant struct {
	PlanID      string          `json:"plan_id"`
	PlanHash    string          `json:"plan_hash"`
	ApprovedBy  string          `json:"approved_by"`
	ApprovedAt  model.Timestamp `json:"approved_at"`
	ExpiresAt   model.Timestamp `json:"expires_at"`
	Nonce       string          `json:"nonce"`
	ScopeDigest string          `json:"scope_digest"`
}

// PolicyDoc is the approval summary handed to Rego.
func (g Grant) PolicyDoc() map[string]any {
	return map[string]any{
		"valid": true, "plan_id": g.PlanID, "plan_hash": g.PlanHash,
		"approved_by":   g.ApprovedBy,
		"expires_at_ns": g.ExpiresAt.UnixNano(),
		"nonce":         g.Nonce,
	}
}

// Authority mints and verifies short-lived, single-use approvals.
type Authority struct {
	mu     sync.Mutex
	secret []byte
	ttl    time.Duration
	used   map[string]bool
}

// NewAuthority requires a secret of at least 16 bytes.
func NewAuthority(secret []byte, ttl time.Duration) (*Authority, error) {
	if len(secret) < 16 {
		return nil, errors.New("approval secret must be at least 16 bytes")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Authority{secret: append([]byte(nil), secret...), ttl: ttl, used: map[string]bool{}}, nil
}

func (a *Authority) sign(payload map[string]any) (string, error) {
	body, err := canonical.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (t Token) payload() map[string]any {
	return map[string]any{
		"token_version": t.TokenVersion,
		"plan_id":       t.PlanID,
		"plan_hash":     t.PlanHash,
		"approved_by":   t.ApprovedBy,
		"approved_at":   model.FormatTime(t.ApprovedAt.Time),
		"expires_at":    model.FormatTime(t.ExpiresAt.Time),
		"nonce":         t.Nonce,
		"scope_digest":  t.ScopeDigest,
	}
}

func scopeDigest(p Plan) (string, error) {
	roots := make([]string, len(p.Roots))
	copy(roots, p.Roots)
	body, err := canonical.Marshal(map[string]any{
		"roots": roots,
		"limits": map[string]any{
			"max_items": p.Limits.MaxItems, "max_bytes": p.Limits.MaxBytes,
		},
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Mint issues a token for a plan. The plan hash is required.
func (a *Authority) Mint(p Plan, approvedBy string, ttl time.Duration) (Token, error) {
	if p.PlanHash == "" {
		return Token{}, ApprovalError("plan has no hash")
	}
	if ttl <= 0 {
		ttl = a.ttl
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return Token{}, err
	}
	digest, err := scopeDigest(p)
	if err != nil {
		return Token{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	token := Token{
		TokenVersion: 1, PlanID: p.PlanID, PlanHash: p.PlanHash,
		ApprovedBy: approvedBy, ApprovedAt: model.Timestamp{Time: now},
		ExpiresAt: model.Timestamp{Time: now.Add(ttl)},
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce), ScopeDigest: digest,
	}
	signature, err := a.sign(token.payload())
	if err != nil {
		return Token{}, err
	}
	token.Signature = signature
	return token, nil
}

// Verify checks a token against a plan. With consume set, the nonce is burned
// so the same approval cannot authorise a second run.
func (a *Authority) Verify(token Token, p Plan, consume bool, now time.Time) (Grant, error) {
	expected, err := a.sign(token.payload())
	if err != nil {
		return Grant{}, err
	}
	if !hmac.Equal([]byte(expected), []byte(token.Signature)) {
		return Grant{}, ApprovalError("approval signature is invalid")
	}
	if token.PlanID != p.PlanID || token.PlanHash != p.PlanHash {
		return Grant{}, ApprovalError("approval is not bound to this plan")
	}
	digest, err := scopeDigest(p)
	if err != nil {
		return Grant{}, err
	}
	if token.ScopeDigest != digest {
		return Grant{}, ApprovalError("approval scope does not match this plan")
	}
	if !now.Before(token.ExpiresAt.Time) {
		return Grant{}, ApprovalError("approval has expired")
	}
	if consume {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.used[token.Nonce] {
			return Grant{}, ApprovalError("approval token was already used")
		}
		a.used[token.Nonce] = true
	}
	return Grant{
		PlanID: token.PlanID, PlanHash: token.PlanHash,
		ApprovedBy: token.ApprovedBy, ApprovedAt: token.ApprovedAt,
		ExpiresAt: token.ExpiresAt, Nonce: token.Nonce, ScopeDigest: token.ScopeDigest,
	}, nil
}
