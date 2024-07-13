/*
 * Copyright (C) 2024, Xiongfa Li.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/xfali/oauth2/v2/clients"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/oauth2"
	http2 "github.com/xfali/oauth2/v2/rpc/http"
	"github.com/xfali/oauth2/v2/servers"
	"github.com/xfali/oauth2/v2/users"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func TestGin(t *testing.T) {
	// web path:
	// http://localhost:8080/oauth2/authorize?response_type=code&redirect_uri=/test/callback&client_id=12L0dnUwdmK
	clientId := "12L0dnUwdmK"
	clientSecret := "VUq_6pxbc5msKxBJggCih9-UjhciE7DZY-RB4XRrnL4="
	ctx := oauth2.NewWithWebCode("/test/login", "/test/authorize")
	_ = ctx.ClientManager.(*clients.DefaultClientManager).CreateClient(entities.ClientInfo{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	})
	um := ctx.UserManager.(*users.DefaultUserManager)
	um.CreateUser("admin", "admin")
	srv := servers.NewGinServer(ctx)
	r := gin.New()
	cli := http2.NewHttpClient(nil, nil)
	site := servers.NewSimpleSite(clientId, clientSecret, cli)
	r.GET("/test/login", func(ctx *gin.Context) {
		site.LoginHtml("/test/login", ctx.Writer, ctx.Request)
	})
	r.GET("/test/authorize", func(ctx *gin.Context) {
		site.AuthorizeHtml("/test/authorize", ctx.Writer, ctx.Request)
	})
	r.POST("/test/authorize", func(ctx *gin.Context) {
		site.Authorize(context.Background(), "http://localhost:8080/oauth2/authorize/web", ctx.Writer, ctx.Request)
	})
	r.POST("/test/login", func(ctx *gin.Context) {
		site.Login(context.Background(), "http://localhost:8080/oauth2/token", "http://localhost:8080/test/authorize", ctx.Writer, ctx.Request)
	})
	r.GET("/test/callback", func(ctx *gin.Context) {
		code := ctx.Query("code")
		t.Logf("code is %s\n", code)
		//io.WriteString(response.ResponseWriter, code)

		client := &http.Client{}

		var req http.Request
		req.ParseForm()
		req.Form.Add("grant_type", oauth2.GrantTypeCode)
		req.Form.Add("code", code)
		req.Form.Add("client_id", clientId)
		req.Form.Add("client_secret", clientSecret)
		bodystr := strings.TrimSpace(req.Form.Encode())
		req2, err := http.NewRequest("POST", addr+"/oauth2/token", strings.NewReader(bodystr))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.Header.Set("Connection", "Keep-Alive")

		resp, err := client.Do(req2)
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}

		ctx.Writer.Write(body)

		token := &entities.Token{}
		_ = json.Unmarshal(body, token)

		err = cli.Authorize(context.Background(), "http://localhost:8080/oauth2/authenticate", token.AccessToken)
		if err != nil {
			t.Log(err)
		}
	})
	srv.RunWithEngine("http://localhost:8080", r)

	s := http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	s.ListenAndServe()
}
