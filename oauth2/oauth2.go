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

package oauth2

import (
	"encoding/json"
	"github.com/emicklei/go-restful"
	"github.com/xfali/goutils/idUtil"
	"github.com/xfali/oauth2/v2/clients"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/datas"
	"github.com/xfali/oauth2/v2/errcodes"
	"github.com/xfali/oauth2/v2/events"
	"github.com/xfali/oauth2/v2/users"
	"github.com/xfali/oauth2/v2/util"
	"github.com/xfali/xlog"
	"io"
	"log"
	"net/http"
	"runtime"
	"time"
)

const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"

	GrantTypeCode              = "authorization_code"
	GrantTypeImplicit          = "implicit"
	GrantTypePassword          = "password"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeDeviceCode        = "device code"
	GrantTypeRefreshToken      = "refresh_token"
)

type ResponseTypeFunc func(auth *OAuth2, request *http.Request, response http.ResponseWriter) error
type GrantTypeFunc func(auth *OAuth2, request *http.Request, response http.ResponseWriter) error
type Writer interface {
	Write(w http.ResponseWriter, o interface{}) error
	WriteError(w http.ResponseWriter, code *errcodes.ErrCode) error
}

type OAuth2 struct {
	Addr           string
	UserManager    users.UserManager
	ClientManager  clients.ClientManager
	DataManager    datas.DataManager
	EventListener  events.EventListener
	CodeExpireTime time.Duration
	logger         xlog.Logger
	LogHttpInfo    bool

	respWriter Writer

	processRespMap    map[string]ResponseTypeFunc
	processRespWebMap map[string]ResponseTypeFunc
	processGrantMap   map[string]GrantTypeFunc
}

func New() *OAuth2 {
	return NewWithWebCode("", "")
}

func NewWithWebCode(loginUrl, authorizeUrl string) *OAuth2 {
	ret := &OAuth2{
		logger:            xlog.GetLogger(),
		UserManager:       users.NewDefaultUserManager(loginUrl, authorizeUrl),
		ClientManager:     clients.NewDefaultClientManager(),
		DataManager:       datas.NewDefaultDataManager(0),
		EventListener:     events.DefaultEventListener,
		CodeExpireTime:    constants.AuthorizationCodeExpireTime,
		LogHttpInfo:       true,
		respWriter:        &defaultWriter{},
		processRespMap:    map[string]ResponseTypeFunc{},
		processRespWebMap: map[string]ResponseTypeFunc{},
		processGrantMap:   map[string]GrantTypeFunc{},
	}

	ret.RegisterRespProcessor(ResponseTypeCode, ProcessRespTypeCode)
	ret.RegisterRespWebProcessor(ResponseTypeCode, ProcessRespTypeWebCode)
	//It is generally not recommended to use the implicit flow
	//ret.RegisterRespProcessor(RESPONSE_TYPE_TOKEN, ProcessRespTypeToken)
	//ret.RegisterRespWebProcessor(RESPONSE_TYPE_CODE, ProcessRespTypeWebCode)
	ret.RegisterRespProcessor(ResponseTypeCode, ProcessRespTypeCode)
	ret.RegisterGrantProcessor(GrantTypeCode, ProcessGrantTypeCode)
	ret.RegisterGrantProcessor(GrantTypePassword, ProcessGrantTypePassword)
	ret.RegisterGrantProcessor(GrantTypeClientCredentials, ProcessGrantTypeClientCredentials)
	ret.RegisterGrantProcessor(GrantTypeRefreshToken, ProcessGrantTypeRefreshToken)

	return ret
}

func (auth *OAuth2) Close() {
	auth.DataManager.Close()
}

func (auth *OAuth2) RegisterRespProcessor(resp_type string, function ResponseTypeFunc) {
	auth.processRespMap[resp_type] = function
}

func (auth *OAuth2) RegisterRespWebProcessor(resp_type string, function ResponseTypeFunc) {
	auth.processRespWebMap[resp_type] = function
}

func (auth *OAuth2) RegisterGrantProcessor(grant_type string, function GrantTypeFunc) {
	auth.processGrantMap[grant_type] = function
}

func (auth *OAuth2) Handle(c *restful.Container) {
	ws := new(restful.WebService)
	//设置匹配的schema和路径
	ws.Path("/oauth2").Consumes("*/*").Produces("*/*")

	//设置不同method对应的方法，参数以及参数描述和类型
	//参数:分为路径上的参数,query层面的参数,Header中的参数
	ws.Route(ws.GET("/authorize").
		To(auth.wrapRouteFunction(auth.authorize)).
		Doc("方法描述：验证").
		Param(ws.QueryParameter("response_type", "应答类型").DataType("string")).
		Param(ws.QueryParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.QueryParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.QueryParameter("scope", "授权范围").DataType("string")).
		Param(ws.QueryParameter("state", "状态").DataType("string")))

	ws.Route(ws.GET("/authorize/web").
		To(auth.wrapRouteFunction(auth.authorizeWeb)).
		Doc("方法描述：验证").
		Param(ws.QueryParameter("response_type", "应答类型").DataType("string")).
		Param(ws.QueryParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.QueryParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.QueryParameter("scope", "授权范围").DataType("string")).
		Param(ws.QueryParameter("state", "状态").DataType("string")))

	ws.Route(ws.POST("/token").
		To(auth.wrapRouteFunction(auth.token)).
		Doc("方法描述：验证").
		Param(ws.HeaderParameter("Authorization", "头部授权信息").DataType("string")).
		Param(ws.BodyParameter("grant_type", "获取类型").DataType("string")).
		Param(ws.BodyParameter("code", "授权码").DataType("string")).
		Param(ws.BodyParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.BodyParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.BodyParameter("client_secret", "客户端密码").DataType("string")).
		Param(ws.BodyParameter("username", "用户名").DataType("string")).
		Param(ws.BodyParameter("password", "用户密码").DataType("string")))

	ws.Route(ws.GET("/authenticate").
		To(auth.wrapRouteFunction(auth.authenticate)).
		Doc("方法描述：验证").
		Param(ws.HeaderParameter("Authorization", "头部授权信息").DataType("string")))

	ws.Route(ws.DELETE("/token").
		To(auth.wrapRouteFunction(auth.revoke)).
		Doc("方法描述：验证").
		Param(ws.HeaderParameter("Authorization", "头部授权信息").DataType("string")).
		Param(ws.BodyParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.BodyParameter("client_secret", "客户端密码").DataType("string")))
	/*
	   //for test
	   ws.Route(ws.POST("/client").
	       To(auth.wrapRouteFunction(auth.createClient)).
	       Doc("方法描述：增加client"))
	   ws.Route(ws.PUT("/client").
	       To(auth.wrapRouteFunction(auth.updateClient)).
	       Doc("方法描述：更新密钥").
	       Param(ws.BodyParameter("client_id", "client_id").DataType("string")))
	   ws.Route(ws.DELETE("/client").
	       To(auth.wrapRouteFunction(auth.deleteClient)).
	       Doc("方法描述：删除client").
	       Param(ws.PathParameter("client_id", "client_id").DataType("string")))

	   ws.Route(ws.GET("/test").
	       To(auth.wrapRouteFunction(auth.test_redirect)).
	       Doc("方法描述：验证").
	       Param(ws.QueryParameter("code", "应答类型").DataType("string")).
	       Param(ws.QueryParameter("state", "状态").DataType("string")))
	*/
	//test end

	c.Add(ws)
}

func (auth *OAuth2) authorize(request *restful.Request, response *restful.Response) {
	response_type := request.QueryParameter("response_type")

	function := auth.processRespMap[response_type]
	if function != nil {
		function(auth, request, response)
		return
	}

	io.WriteString(response.ResponseWriter, "response_type Not found this would be a normal response")
}

func (auth *OAuth2) authorizeWeb(request *restful.Request, response *restful.Response) {
	response_type := request.QueryParameter("response_type")

	function := auth.processRespWebMap[response_type]
	if function != nil {
		function(auth, request, response)
		return
	}

	io.WriteString(response.ResponseWriter, "response_type(web) Not found this would be a normal response")
}

func (auth *OAuth2) token(request *restful.Request, response *restful.Response) {
	grant_type, err := request.BodyParameter("grant_type")
	if err != nil {
		response.WriteErrorString(http.StatusBadRequest, "grant_type is missing")
	}

	function := auth.processGrantMap[grant_type]
	if function != nil {
		function(auth, request, response)
		return
	}

	io.WriteString(response.ResponseWriter, "grant_type this would be a normal response")
}

func (auth *OAuth2) authenticate(request *restful.Request, response *restful.Response) {
	ProcessAccessToken(auth, request, response)
}

func (auth *OAuth2) revoke(request *restful.Request, response *restful.Response) {
	ProcessRevokeToken(auth, request, response)
}

/*
func (auth *OAuth2) createClient(request *restful.Request, response *restful.Response) {
    clientInfo, err := auth.ClientManager.CreateClient()
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    b, err := json.Marshal(clientInfo)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    response.Write(b)
}

func (auth *OAuth2) updateClient(request *restful.Request, response *restful.Response) {
    client_id := request.PathParameter("client_id")
    secret, err := auth.ClientManager.UpdateClient(client_id)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    io.WriteString(response.ResponseWriter, secret)
}

func (auth *OAuth2) deleteClient(request *restful.Request, response *restful.Response) {
    client_id := request.PathParameter("client_id")
    err := auth.ClientManager.DeleteClient(client_id)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    response.WriteHeader(http.StatusOK)
}
*/

func (auth *OAuth2) wrapRouteFunction(function restful.RouteFunction) restful.RouteFunction {
	return func(request *restful.Request, response *restful.Response) {
		defer func() {
			if err := recover(); err != nil && err != http.ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				auth.logger.Errorf("http: panic serving %v: %v\n%s", request.Request.RemoteAddr, err, buf)
				response.WriteErrorString(http.StatusInternalServerError, "内部错误")
			}
		}()

		id := ""
		if auth.LogHttpInfo {
			id = idUtil.RandomId(32)
			util.LogRequest(id, auth.logger.Infof, request)
		}

		function(request, response)

		if auth.LogHttpInfo {
			util.LogResponse(id, auth.logger.Infof, response)
		}
	}
}

func (auth *OAuth2) RunWithContainer(wsContainer *restful.Container, host, port string) {
	auth.Addr = host + ":" + port
	// 跨域过滤器
	cors := restful.CrossOriginResourceSharing{
		ExposeHeaders:  []string{"X-My-Header"},
		AllowedHeaders: []string{"Content-Type", "Accept"},
		AllowedMethods: []string{"GET", "POST"},
		CookiesAllowed: false,
		Container:      wsContainer}
	wsContainer.Filter(cors.Filter)

	// Add container filter to respond to OPTIONS
	wsContainer.Filter(wsContainer.OPTIONSFilter)

	//config := swagger.Config{
	//    WebServices:    restful.DefaultContainer.RegisteredWebServices(), // you control what services are visible
	//    WebServicesUrl: "http://localhost:8080",
	//    ApiPath:        "/apidocs.json",
	//    ApiVersion:     "V1.0",
	//    // Optionally, specify where the UI is located
	//    SwaggerPath:     "/apidocs/",
	//    SwaggerFilePath: "D:/gowork/oauth2/doublegao/experiment/restful/dist"}
	//swagger.RegisterSwaggerService(config, wsContainer)
	//swagger.InstallSwaggerService(config)

	auth.Handle(wsContainer)
	defer auth.Close()

	log.Println("start listening on localhost:8080")
	server := &http.Server{Addr: ":" + port, Handler: wsContainer}
	defer server.Close()
	log.Fatal(server.ListenAndServe())
}

func (auth *OAuth2) Run(host, port string) {
	auth.RunWithContainer(restful.NewContainer(), host, port)
}

func Run(host, port string) {
	New().Run(host, port)
}

type defaultWriter struct {
}

func (dw *defaultWriter) Write(w http.ResponseWriter, o interface{}) error {
	if s, ok := o.(string); ok {
		_, err := io.WriteString(w, s)
		return err
	} else {
		v, err := json.Marshal(o)
		if err != nil {
			return err
		}
		_, err = w.Write(v)
		return err
	}
}

func (dw *defaultWriter) WriteError(w http.ResponseWriter, code *errcodes.ErrCode) error {
	if code != nil {
		w.WriteHeader(code.HttpStatus)
		_, err := w.Write([]byte(code.Error()))
		return err
	}
	return nil
}
