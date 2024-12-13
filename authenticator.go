// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/go-jose/go-jose/v3"
	"github.com/pardot/oidc"
	"github.com/pardot/oidc/discovery"
	"golang.org/x/net/http/httpproxy"
)

type authenticator struct {
	// UserTemplate is a template that, when rendered with the JWT claims, should
	// match the user being authenticated.
	//
	// `{{.Subject}}` is used by default if not set.
	UserTemplate string

	// GroupsClaimKey is the name of the key within the token claims that
	// specifies which groups a user is a member of.
	//
	// `groups` is used by default if not set.
	GroupsClaimKey string

	// AuthorizedGroups is a list of groups required for authentication to pass.
	// A user must be a member of at least one of the groups in the list, if
	// specified.
	//
	// If the list is empty, group membership is not required for authentication
	// to pass.
	AuthorizedGroups []string

	// RequireACRs is a list of required values of the acr claim in the token for
	// authentication to pass. At least one of the acrs must be present if specified
	//
	// If the list is empty, the ACR value is not checked.
	RequireACRs []string

	verifier *oidc.Verifier
	aud      string
}

func discoverAuthenticator(ctx context.Context, issuer string, aud string, httpProxy string, localKeySetPath string) (*authenticator, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if httpProxy != "" {
		// Use no_proxy from environment, if present, but override proxy URL
		cfg := httpproxy.FromEnvironment()
		cfg.HTTPProxy = httpProxy
		cfg.HTTPSProxy = httpProxy

		proxyFunc := cfg.ProxyFunc()
		transport.Proxy = func(r *http.Request) (*url.URL, error) {
			return proxyFunc(r.URL)
		}
	}

	var keySource oidc.KeySource

	if issuer != "" {
		client, err := discovery.NewClient(ctx, issuer, discovery.WithHTTPClient(&http.Client{
			Transport: transport,
		}))
		if err != nil {
			if localKeySetPath != "" {
				return nil, fmt.Errorf("discovering verifier: %v", err)
			} else {
				// TODO : emit warning via pamSyslog
			}
		} else {
			// if no `error, save the fetched key set to the local path
			keys, err := client.PublicKeys(ctx)
			if err != nil {
				return nil, fmt.Errorf("fetching public keys: %v", err)
			}
			keyset, err := json.Marshal(keys)
			if err != nil {
				return nil, fmt.Errorf("marshaling key set: %v", err)
			}
			if err := os.WriteFile(localKeySetPath, keyset, 0600); err != nil {
				return nil, fmt.Errorf("caching key set: %v", err)
			}
			keySource = client
		}
	}

	if keySource == nil && localKeySetPath != "" {
		var keys jose.JSONWebKeySet
		keyset, err := os.ReadFile(localKeySetPath)
		if err != nil {
			return nil, fmt.Errorf("reading key set: %v", err)
		}
		if err := json.Unmarshal(keyset, &keys); err != nil {
			return nil, fmt.Errorf("unmarshaling key set: %v", err)
		}
		if len(keys.Keys) == 0 {
			return nil, fmt.Errorf("no keys in key set")
		}
		keySource = oidc.NewStaticKeysource(keys)
	}

	verifier := oidc.NewVerifier(issuer, keySource)
	return &authenticator{
		verifier: verifier,
		aud:      aud,
	}, nil
}

// Authenticate authenticates a user with the provided token.
func (a *authenticator) Authenticate(ctx context.Context, user string, token string) error {
	claims, err := a.verifier.VerifyRaw(ctx, a.aud, token)
	if err != nil {
		return fmt.Errorf("verifying token: %v", err)
	}

	userTemplate := "{{.Subject}}"
	if a.UserTemplate != "" {
		userTemplate = a.UserTemplate
	}

	userTmpl, err := template.New("").Funcs(template.FuncMap{
		"trimPrefix": func(prefix, s string) string { return strings.TrimPrefix(s, prefix) },
		"trimSuffix": func(suffix, s string) string { return strings.TrimSuffix(s, suffix) },
	}).Parse(userTemplate)
	if err != nil {
		return fmt.Errorf("parsing user template: %v", err)
	}

	buf := new(bytes.Buffer)
	if err := userTmpl.Execute(buf, claims); err != nil {
		return fmt.Errorf("executing user template: %v", err)
	}

	wantUser := buf.String()
	if wantUser != user {
		return fmt.Errorf("expected user %q but is authenticating as %q", wantUser, user)
	}

	// Validate AuthorizedGroups / GroupClaimsKey
	if len(a.AuthorizedGroups) > 0 {
		groupsClaimKey := "groups"
		if len(a.GroupsClaimKey) > 0 {
			groupsClaimKey = a.GroupsClaimKey
		}

		groupsClaim, ok := claims.Extra[groupsClaimKey].([]interface{})
		if !ok {
			return fmt.Errorf("user is not member of any groups, but one of %v is required", a.AuthorizedGroups)
		}

		groups := make([]string, 0, len(groupsClaim))
		for _, groupVal := range groupsClaim {
			if group, ok := groupVal.(string); ok {
				groups = append(groups, group)
			}
		}
		if !isMemberOfAtLeastOneGroup(a.AuthorizedGroups, groups) {
			return fmt.Errorf("user is member of %v, but one of %v is required", groups, a.AuthorizedGroups)
		}
	}

	// Validate RequireACRs
	if len(a.RequireACRs) > 0 {
		if !isACRPresent(a.RequireACRs, claims.ACR) {
			return fmt.Errorf("acr is %q, but one of %v is required", claims.ACR, a.RequireACRs)
		}
	}

	return nil
}

func isMemberOfAtLeastOneGroup(authorizedGroups []string, groups []string) bool {
	for _, wantGroup := range authorizedGroups {
		for _, group := range groups {
			if wantGroup == group {
				return true
			}
		}
	}

	return false
}

func isACRPresent(authorizedACRs []string, acr string) bool {
	for _, wantACR := range authorizedACRs {
		if wantACR == acr {
			return true
		}
	}

	return false
}
