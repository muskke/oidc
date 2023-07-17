package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

// XXX: 模拟IAM，同时作为服务端处理sso web、oidc客户端逻辑和作为客户端处理第三方认证（如Github、MinIO、企业微信等）

// 初始化变量配置
var (
	/**
	* 作为客户端侧配置
	 */
	// 服务端认证地址
	Issuer = "http://localhost:9998/"
	// 服务端回调地址
	CallbackPath = "/auth/callback"
	// 客户端在服务端注册的ClientID
	ClientID = "web"
	// 客户端在服务端注册的ClientSecret
	ClientSecret = ""
	// JWT签名文件路径
	JWTSignKeyPath = ""
	// 授权范围
	Scopes = []string{
		"openid",
		"profile",
		"email",
	}
	// 客户端Cookie Key
	ClientCookieKey = []byte("cookie-test12345") // 长度必须为16字节

	/**
	* 作为服务端侧配置
	 */
	Port = 9999
)

func main() {

	// XXX: test github auth
	// Issuer, ClientID, ClientSecret = "https://github.com/login/oauth/authorize", "d4f2cba917cc6b7bea8e", ""

	// 设置客户端重定向URI
	redirectURI := fmt.Sprintf("http://localhost:%v%v", Port, CallbackPath)
	// 设置客户端Cookie Handler
	cookieHandler := httphelper.NewCookieHandler(ClientCookieKey, ClientCookieKey, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	// if clientSecret == "" {
	// options = append(options, rp.WithPKCE(cookieHandler))
	// }
	if JWTSignKeyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(JWTSignKeyPath)))
	}

	// OAuth2 认证服务器配置
	provider, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token"},
		RedirectURL:  redirectURI,
		Scopes:       []string{"repo", "repo_deployment"},
	}, options...)

	// // OIDC 认证服务发现配置
	// provider, err := rp.NewRelyingPartyOIDC(Issuer, ClientID, ClientSecret, redirectURI, Scopes, options...)
	if err != nil {
		fmt.Printf("error creating provider %s \n", err.Error())
		os.Exit(1)
	}

	// 用户登录客户端认证请求
	http.Handle("/login", rp.AuthURLHandler(func() string {
		return uuid.New().String()
	}, provider, rp.WithPromptURLParam("Welcome back!")))

	// 用户登录回调，返回用户信息
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}

	// 接受服务端认证回调，得到授权码->拿授权码换取Token, 使用token执行回调方法返回用户信息
	http.Handle(CallbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), provider))

	lis := fmt.Sprintf("127.0.0.1:%d", Port)
	fmt.Printf("listening on http://%s/ \n", lis)
	fmt.Println(http.ListenAndServe(lis, nil))
}
