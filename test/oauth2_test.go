/*
 * Copyright (C) 2019-2024, Xiongfa Li.
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
	"errors"
	"fmt"
	"github.com/emicklei/go-restful"
	"github.com/xfali/oauth2/v2/clients"
	"github.com/xfali/oauth2/v2/oauth2"
	"github.com/xfali/oauth2/v2/users"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
)

type test struct {
	auth         *oauth2.OAuth2
	um           *users.DefaultUserManager
	cm           *clients.DefaultClientManager
	clientId     string
	clientSecret string
}

//http://localhost:8080/oauth2/authorize?response_type=code&redirect_uri=http://localhost:8080/test/redirect&scope=test&state=123&client_id=CoBz7Z15ai

func TestOauth2(t *testing.T) {
	auth := oauth2.New()
	test := test{auth: auth}

	cm := clients.NewDefaultClientManager()
	ClientInfo, _ := cm.CreateClient()
	fmt.Printf("client_id: %s\nclient_secret: %s\n", ClientInfo.ClientId, ClientInfo.ClientSecret)
	auth.ClientManager = cm
	test.cm = cm
	test.clientId = ClientInfo.ClientId
	test.clientSecret = ClientInfo.ClientSecret

	um := users.NewDefaultUserManager("/test/login", "/test/authorize")
	um.CreateUser("admin", "admin")
	fmt.Printf("username: admin\npassword: admin\n")
	auth.UserManager = um
	test.um = um

	container := restful.NewContainer()
	test.initTestContainer(container)

	auth.RunWithContainer(container, "http://localhost", "8080")
}

func (t *test) initTestContainer(container *restful.Container) {
	ws := new(restful.WebService)
	//设置匹配的schema和路径
	ws.Path("/test").Consumes("*/*").Produces("*/*")

	ws.Route(ws.GET("/login").
		To(t.testLoginHtml))

	ws.Route(ws.GET("/authorize").
		To(t.testAuthorizeHtml))

	ws.Route(ws.POST("/login").
		To(t.testLogin)).
		Param(ws.BodyParameter("username", "用户名").DataType("string")).
		Param(ws.BodyParameter("password", "密码").DataType("string"))

	ws.Route(ws.GET("/redirect").
		To(t.testRedirect))

	ws.Route(ws.POST("/backend").
		To(t.backend))

	container.Add(ws)
}

func (t *test) testRedirect(request *restful.Request, response *restful.Response) {
	code := request.QueryParameter("code")
	log.Printf("code is %s\n", code)
	//io.WriteString(response.ResponseWriter, code)

	client := &http.Client{}

	var req http.Request
	req.ParseForm()
	req.Form.Add("grant_type", oauth2.GrantTypeCode)
	req.Form.Add("code", code)
	req.Form.Add("client_id", t.clientId)
	req.Form.Add("client_secret", t.clientSecret)
	bodystr := strings.TrimSpace(req.Form.Encode())
	req2, err := http.NewRequest("POST", t.auth.Addr+"/oauth2/token", strings.NewReader(bodystr))
	if err != nil {
		response.WriteError(http.StatusBadRequest, err)
		return
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Connection", "Keep-Alive")

	resp, err := client.Do(req2)
	if err != nil {
		response.WriteError(http.StatusBadRequest, err)
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		response.WriteError(http.StatusBadRequest, err)
		return
	}

	response.Write(body)

}

func (t *test) testLoginHtml(request *restful.Request, response *restful.Response) {
	b, err := ioutil.ReadFile(getResourcePath("login.html"))
	if err != nil {
		response.WriteError(http.StatusBadRequest, err)
	}
	htmlStr := string(b)
	param := "/test/login?" + request.Request.URL.RawQuery
	htmlStr = strings.Replace(htmlStr, "LOGIN_API_PATH", param, 1)

	io.WriteString(response.ResponseWriter, htmlStr)
}

func (t *test) testAuthorizeHtml(request *restful.Request, response *restful.Response) {
	b, err := ioutil.ReadFile(getResourcePath("authorize.html"))
	if err != nil {
		response.WriteError(http.StatusBadRequest, err)
	}
	htmlStr := string(b)
	param := "/test/backend?" + request.Request.URL.RawQuery
	htmlStr = strings.Replace(htmlStr, "AUTHORIZE_API_PATH", param, 1)

	io.WriteString(response.ResponseWriter, htmlStr)
}

func (t *test) testLogin(request *restful.Request, response *restful.Response) {
	username, _ := request.BodyParameter("username")
	password, _ := request.BodyParameter("password")
	log.Printf("usernam is %s password %s\n", username, password)

	err := t.um.CheckUser(username, password)
	if err == nil {
		c := http.Cookie{
			Name:     "JSESSIONID",
			Value:    "12345",
			HttpOnly: true,
			Path:     "/",
		}
		// 把cookie写入客户端
		http.SetCookie(response.ResponseWriter, &c)

		query := request.Request.URL.RawQuery
		callback := request.QueryParameter("callback")
		callback = callback + "?" + query

		http.Redirect(response.ResponseWriter, request.Request, callback, http.StatusFound)
		return
	}

	response.WriteError(http.StatusUnauthorized, errors.New("nnn"))
}

func (t *test) backend(request *restful.Request, response *restful.Response) {
	params := request.Request.URL.RawQuery
	url := request.QueryParameter("callback") + "?" + params
	http.Redirect(response.ResponseWriter, request.Request, url, http.StatusFound)
}

func getResourcePath(file string) string {
	path := os.Getenv("resource.path")
	return path + "/html/" + file
}
