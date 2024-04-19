package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"kubesphere.io/kubesphere/pkg/server/options"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"golang.org/x/oauth2"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
)

var azureServer *httptest.Server

func TestAzure(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Azure Identity Provider Suite")
}

var _ = BeforeSuite(func(done Done) {
	azureServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]interface{}
		switch r.RequestURI {
		case "/login/oauth/access_token":
			data = map[string]interface{}{
				"access_token": "e72e16c7e42f292c6912e7710c838347ae178b4a",
				"scope":        "user.read,openid,email",
				"token_type":   "bearer",
			}
		case "/user":
			data = map[string]interface{}{
				"family_name": "R",
				"given_name":  "Ron",
				"name":        "Ron",
				"email":       "ron@myx.finance",
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("not implemented"))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}))
	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	gexec.KillAndWait(5 * time.Second)
	azureServer.Close()
})

var _ = Describe("Azure", func() {
	Context("Azure", func() {
		var (
			provider identityprovider.OAuthProvider
			err      error
		)
		It("should configure successfully", func() {
			configJSON := `{
				"clientID": "de6ff8bed0304e487b6e",
				"clientSecret": "2b70536f79ec8d2939863509d05e2a71c268b9af",
				"redirectURL": "https://ks-console.kubesphere-system.svc/oauth/redirect/azure",
				"scopes": ["user.read", "openid", "email"]
			}`
			config := mustUnmarshalJSON(configJSON)
			factory := oauthProviderFactory{}
			provider, err = factory.Create(config)
			Expect(err).Should(BeNil())
			expected := &azure{
				ClientID:     "de6ff8bed0304e487b6e",
				ClientSecret: "2b70536f79ec8d2939863509d05e2a71c268b9af",
				Endpoint: endpoint{
					AuthURL:     authURL,
					TokenURL:    tokenURL,
					UserInfoURL: userInfoURL,
				},
				RedirectURL: "https://ks-console.kubesphere-system.svc/oauth/redirect/azure",
				Scopes:      []string{"user.read", "openid", "email"},
				Config: &oauth2.Config{
					ClientID:     "de6ff8bed0304e487b6e",
					ClientSecret: "2b70536f79ec8d2939863509d05e2a71c268b9af",
					Endpoint: oauth2.Endpoint{
						AuthURL:  authURL,
						TokenURL: tokenURL,
					},
					RedirectURL: "https://ks-console.kubesphere-system.svc/oauth/redirect/azure",
					Scopes:      []string{"user.read", "openid", "email"},
				},
			}
			Expect(provider).Should(Equal(expected))
		})
		It("should configure successfully", func() {
			config := options.DynamicOptions{
				"clientID":           "de6ff8bed0304e487b6e",
				"clientSecret":       "2b70536f79ec8d2939863509d05e2a71c268b9af",
				"redirectURL":        "https://ks-console.kubesphere-system.svc/oauth/redirect/azure",
				"insecureSkipVerify": true,
				"endpoint": options.DynamicOptions{
					"authURL":     fmt.Sprintf("%s/login/oauth/authorize", azureServer.URL),
					"tokenURL":    fmt.Sprintf("%s/login/oauth/access_token", azureServer.URL),
					"userInfoURL": fmt.Sprintf("%s/user", azureServer.URL),
				},
			}
			factory := oauthProviderFactory{}
			provider, err = factory.Create(config)
			Expect(err).Should(BeNil())
			expected := options.DynamicOptions{
				"clientID":           "de6ff8bed0304e487b6e",
				"clientSecret":       "2b70536f79ec8d2939863509d05e2a71c268b9af",
				"redirectURL":        "https://ks-console.kubesphere-system.svc/oauth/redirect/azure",
				"insecureSkipVerify": true,
				"endpoint": options.DynamicOptions{
					"authURL":     fmt.Sprintf("%s/login/oauth/authorize", azureServer.URL),
					"tokenURL":    fmt.Sprintf("%s/login/oauth/access_token", azureServer.URL),
					"userInfoURL": fmt.Sprintf("%s/user", azureServer.URL),
				},
			}
			Expect(config).Should(Equal(expected))
		})
		It("should login successfully", func() {
			url, _ := url.Parse("https://ks-console.kubesphere-system.svc/oauth/redirect/test?code=00000")
			req := &http.Request{URL: url}
			identity, err := provider.IdentityExchangeCallback(req)
			Expect(err).Should(BeNil())
			Expect(identity.GetUserID()).Should(Equal("ron@myx.finance"))
			Expect(identity.GetUsername()).Should(Equal("Ron"))
			Expect(identity.GetEmail()).Should(Equal("ron@myx.finance"))
		})
	})
})

func mustUnmarshalJSON(data string) options.DynamicOptions {
	var dynamicOptions options.DynamicOptions
	_ = json.Unmarshal([]byte(data), &dynamicOptions)
	return dynamicOptions
}
