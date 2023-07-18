package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/text/language"

	"sso/third_auth/server/storage"

	"github.com/zitadel/oidc/v2/pkg/op"
)

var (
	hostnames = []string{
		"localhost",  //note that calling 127.0.0.1 / ::1 won't work as the hostname does not match
		"oidc.local", //add this to your hosts file (pointing to 127.0.0.1)
		//feel free to add more...
	}

	//the OpenID Provider requires a 32-byte key for (token) encryption, be sure to create a proper crypto random key and manage it securely!
	CryptoKey     = sha256.Sum256([]byte("test")) // OpenID的token加密Key
	port          = "9998"                        // 服务端口
	pathLoggedOut = "/logged-out"                 // 登出页路由
)

func init() {
	storage.RegisterClients()
}

const (
	queryAuthRequestID = "authRequestID" // 认证请求ID参数
)

var (
	// 登录页模板
	loginTmpl, _ = template.New("login").Parse(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Login</title>
		</head>
		<body style="display: flex; align-items: center; justify-content: center; height: 100vh;">
			<form method="POST" action="/login/username" style="height: 200px; width: 200px;">
				<input type="hidden" name="id" value="{{.ID}}">
				<div>
					<label for="username">Username:</label>
					<input id="username" name="username" style="width: 100%">
				</div>
				<div>
					<label for="password">Password:</label>
					<input id="password" name="password" style="width: 100%">
				</div>
				<p style="color:red; min-height: 1rem;">{{.Error}}</p>
				<button type="submit">Login</button>
			</form>
		</body>
	</html>`)
)

type login struct {
	authenticate authenticate
	router       *mux.Router
	callback     func(context.Context, string) string
}

func main() {
	ctx := context.Background()

	// 缓存发行商
	issuers := make([]string, len(hostnames))
	for i, hostname := range hostnames {
		issuers[i] = fmt.Sprintf("http://%s:%s/", hostname, port)
	}

	// 创建一个能够处理多个颁发者各种检查和状态操作的存储接口
	storage := storage.NewMultiStorage(issuers)

	// 基于存储接口创建OpenID供应商接口
	provider, err := newDynamicOP(ctx, storage, CryptoKey)
	if err != nil {
		log.Fatal(err)
	}

	// 创建一个简单的用户登录认证拦截器（提供简单的渲染UI页面），认证成功后向客户端回调地址颁发授权码
	l := NewLogin(storage, op.AuthCallbackURL(provider), op.NewIssuerInterceptor(provider.IssuerFromRequest))

	// 将所有/login的调用定向到登录web UI
	router := mux.NewRouter()
	router.PathPrefix("/login/").Handler(http.StripPrefix("/login", l.router))

	// 由于op需要，创建一个简单的模拟用户注销页面
	router.HandleFunc(pathLoggedOut, func(w http.ResponseWriter, req *http.Request) {
		_, err := w.Write([]byte("signed out successfully"))
		if err != nil {
			log.Printf("error serving logged out page: %v", err)
		}
	})

	// 将OP的HTTP处理程序全部注册到根路由
	router.PathPrefix("/").Handler(provider.HttpHandler())

	// 启动服务
	server := &http.Server{Addr: ":" + port, Handler: router}
	if err = server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()

}

// newDynamicOP 将使用给定的加密密钥在指定端口上为本地主机创建一个 OpenID 提供程序和预定义的默认注销 URI
func newDynamicOP(ctx context.Context, storage op.Storage, key [32]byte) (*op.Provider, error) {
	config := &op.Config{
		CryptoKey: key,

		//will be used if the end_session endpoint is called without a post_logout_redirect_uri
		DefaultLogoutRedirectURI: pathLoggedOut,

		//enables code_challenge_method S256 for PKCE (and therefore PKCE in general)
		CodeMethodS256: true,

		//enables additional client_id/client_secret authentication by form post (not only HTTP Basic Auth)
		AuthMethodPost: true,

		//enables additional authentication by using private_key_jwt
		AuthMethodPrivateKeyJWT: true,

		//enables refresh_token grant use
		GrantTypeRefreshToken: true,

		//enables use of the `request` Object parameter
		RequestObjectSupported: true,

		//this example has only static texts (in English), so we'll set the here accordingly
		SupportedUILocales: []language.Tag{language.English},
	}
	handler, err := op.NewDynamicOpenIDProvider("/", config, storage,
		//we must explicitly allow the use of the http issuer
		op.WithAllowInsecure(),
		//as an example on how to customize an endpoint this will change the authorization_endpoint from /authorize to /auth
		op.WithCustomAuthEndpoint(op.NewEndpoint("auth")),
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}

func NewLogin(authenticate authenticate, callback func(context.Context, string) string, issuerInterceptor *op.IssuerInterceptor) *login {
	l := &login{
		authenticate: authenticate,
		callback:     callback,
	}
	l.createRouter(issuerInterceptor)
	return l
}

func (l *login) createRouter(issuerInterceptor *op.IssuerInterceptor) {
	l.router = mux.NewRouter()
	l.router.Path("/username").Methods("GET").HandlerFunc(l.loginHandler)
	l.router.Path("/username").Methods("POST").HandlerFunc(issuerInterceptor.HandlerFunc(l.checkLoginHandler))
}

type authenticate interface {
	CheckUsernamePassword(ctx context.Context, username, password, id string) error
}

func (l *login) loginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
		return
	}
	//the oidc package will pass the id of the auth request as query parameter
	//we will use this id through the login process and therefore pass it to the  login page
	renderLogin(w, r.FormValue(queryAuthRequestID), nil)
}

func renderLogin(w http.ResponseWriter, id string, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	data := &struct {
		ID    string
		Error string
	}{
		ID:    id,
		Error: errMsg,
	}
	err = loginTmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (l *login) checkLoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	id := r.FormValue("id")
	err = l.authenticate.CheckUsernamePassword(r.Context(), username, password, id)
	if err != nil {
		renderLogin(w, id, err)
		return
	}
	http.Redirect(w, r, l.callback(r.Context(), id), http.StatusFound)
}
