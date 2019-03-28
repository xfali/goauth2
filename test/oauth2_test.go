/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package test

import (
    "fmt"
    "github.com/emicklei/go-restful"
    "github.com/xfali/oauth2/buildin"
    "github.com/xfali/oauth2/oauth2"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strings"
    "testing"
)

type test struct {
    auth     *oauth2.OAuth2
    um       *buildin.DefaultUserManager
    cm       *buildin.DefaultClientManager
    clientId string
}

func TestOauth2(t *testing.T) {
    auth := oauth2.New()
    test := test{auth: auth}

    cm := buildin.NewDefaultClientManager()
    ClientInfo, _ := cm.CreateClient()
    fmt.Printf("client_id: %s\nclient_secret: %s\n", ClientInfo.ClientId, ClientInfo.ClientSecret)
    auth.ClientManager = cm
    test.cm = cm
    test.clientId = ClientInfo.ClientId

    um := buildin.NewDefaultUserManager("/test/login", "/test/authorize")
    um.CreateUser("admin", "admin")
    fmt.Printf("username: admin\npassword: admin\n")
    auth.UserManager = um
    test.um = um

    container := restful.NewContainer()
    test.initTestContainer(container)

    auth.RunWithContainer(container, "localhost", "8080")
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
}

func (t *test) testLoginHtml(request *restful.Request, response *restful.Response) {
    b, err := ioutil.ReadFile(getResourcePath("login.html"))
    if err != nil {
        response.WriteError(http.StatusBadRequest, err)
    }

    response.Write(b)
}

func (t *test) testAuthorizeHtml(request *restful.Request, response *restful.Response) {
    b, err := ioutil.ReadFile(getResourcePath("authorize.html"))
    if err != nil {
        response.WriteError(http.StatusBadRequest, err)
    }

    response.Write(b)
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
        }
        // 把cookie写入客户端
        http.SetCookie(response.ResponseWriter, &c)
        //http.Redirect(response.ResponseWriter, request.Request, "/test/authorize", http.StatusFound)
    }

    response.WriteError(http.StatusUnauthorized, err)
}


func (t *test) backend(request *restful.Request, response *restful.Response) {
    request.Request.Cookie("login")
    client := &http.Client{}

    url := "http://localhost:8080/oauth2/authorize?response_type=code&redirect_uri=http://localhost:8080/test/redirect&scope=test&state=123&client_id=" + t.clientId
    req, err := http.NewRequest("GET", url, strings.NewReader("name=cjb"))
    if err != nil {
        // handle error
    }

    resp, err := client.Do(req)

    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        // handle error
    }

    response.Write(body)
}

func getResourcePath(file string) string {
    path := os.Getenv("resource.path")
    return path + "/html/" + file
}
