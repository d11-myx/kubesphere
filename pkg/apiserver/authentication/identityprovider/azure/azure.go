package azure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/server/options"
)

const (
	userInfoURL = "https://login.microsoftonline.com/defa9b90-ea95-4843-b456-524c1ab0ec7e/openid/userinfo"
	authURL     = "https://login.microsoftonline.com/defa9b90-ea95-4843-b456-524c1ab0ec7e/oauth2/authorize"
	tokenURL    = "https://login.microsoftonline.com/defa9b90-ea95-4843-b456-524c1ab0ec7e/oauth2/token"
)

func init() {
	identityprovider.RegisterOAuthProvider(&oauthProviderFactory{})
}

type azure struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"-"`

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.endpoint.
	Endpoint endpoint `json:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL"`

	// Used to turn off TLS certificate checks
	InsecureSkipVerify bool `json:"insecureSkipVerify"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes"`

	Config *oauth2.Config `json:"-"`
}

// endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type endpoint struct {
	AuthURL     string `json:"authURL"`
	TokenURL    string `json:"tokenURL"`
	UserInfoURL string `json:"userInfoURL"`
}

type azureIdentity struct {
	Name      string `json:"name"`
	Sub       string `json:"sub"`
	GivenName string `json:"given_name"`
	Email     string `json:"email"`
}

type oauthProviderFactory struct {
}

func (a azureIdentity) GetUserID() string {
	return a.Sub
}

func (a azureIdentity) GetUsername() string {
	return a.GivenName
}

func (a azureIdentity) GetEmail() string {
	return a.Email
}

func (o *oauthProviderFactory) Type() string {
	return "AzureIdentityProvider"
}

func (o *oauthProviderFactory) Create(opts options.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var a azure
	if err := mapstructure.Decode(opts, &a); err != nil {
		return nil, err
	}

	if a.Endpoint.AuthURL == "" {
		a.Endpoint.AuthURL = authURL
	}
	if a.Endpoint.TokenURL == "" {
		a.Endpoint.TokenURL = tokenURL
	}
	if a.Endpoint.UserInfoURL == "" {
		a.Endpoint.UserInfoURL = userInfoURL
	}
	// fixed options
	opts["endpoint"] = options.DynamicOptions{
		"authURL":     a.Endpoint.AuthURL,
		"tokenURL":    a.Endpoint.TokenURL,
		"userInfoURL": a.Endpoint.UserInfoURL,
	}
	a.Config = &oauth2.Config{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  a.Endpoint.AuthURL,
			TokenURL: a.Endpoint.TokenURL,
		},
		RedirectURL: a.RedirectURL,
		Scopes:      a.Scopes,
	}
	return &a, nil
}

func (a *azure) IdentityExchangeCallback(req *http.Request) (identityprovider.Identity, error) {
	code := req.URL.Query().Get("code")
	ctx := req.Context()
	if a.InsecureSkipVerify {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	token, err := a.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(a.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var azureIdentity azureIdentity
	err = json.Unmarshal(data, &azureIdentity)
	if err != nil {
		return nil, err
	}

	return azureIdentity, nil
}
