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

package servers

import (
	"github.com/emicklei/go-restful"
	"github.com/xfali/goutils/idUtil"
	"github.com/xfali/oauth2/v2/configs"
	"github.com/xfali/oauth2/v2/oauth2"
	"github.com/xfali/oauth2/v2/util"
	"github.com/xfali/xlog"
	"log"
	"net/http"
	"runtime"
)

type RestfulServer struct {
	logger xlog.Logger
	ctx    *oauth2.OAuth2Context

	logHttpInfo bool
	addr        string
}

func NewRestfulServer(ctx *oauth2.OAuth2Context) *RestfulServer {
	ret := &RestfulServer{
		logger: xlog.GetLogger(),
		ctx:    ctx,
	}
	return ret
}

func (s *RestfulServer) Handle(c *restful.Container) {
	ws := new(restful.WebService)
	//设置匹配的schema和路径
	ws.Path("/oauth2").Consumes("*/*").Produces("*/*")

	//设置不同method对应的方法，参数以及参数描述和类型
	//参数:分为路径上的参数,query层面的参数,Header中的参数
	ws.Route(ws.GET("/authorize").
		To(s.wrapRouteFunction(s.ctx.Authorize)).
		Doc("方法描述：验证").
		Param(ws.QueryParameter("response_type", "应答类型").DataType("string")).
		Param(ws.QueryParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.QueryParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.QueryParameter("scope", "授权范围").DataType("string")).
		Param(ws.QueryParameter("state", "状态").DataType("string")))

	ws.Route(ws.GET("/authorize/web").
		To(s.wrapRouteFunction(s.ctx.AuthorizeWeb)).
		Doc("方法描述：验证").
		Param(ws.QueryParameter("response_type", "应答类型").DataType("string")).
		Param(ws.QueryParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.QueryParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.QueryParameter("scope", "授权范围").DataType("string")).
		Param(ws.QueryParameter("state", "状态").DataType("string")))

	ws.Route(ws.POST("/token").
		To(s.wrapRouteFunction(s.ctx.Token)).
		Doc("方法描述：验证").
		Param(ws.HeaderParameter(configs.OAuth2BasicAuthorizationKey, "头部授权信息").DataType("string")).
		Param(ws.BodyParameter("grant_type", "获取类型").DataType("string")).
		Param(ws.BodyParameter("code", "授权码").DataType("string")).
		Param(ws.BodyParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.BodyParameter("client_id", "客户端ID").DataType("string")).
		Param(ws.BodyParameter("client_secret", "客户端密码").DataType("string")).
		Param(ws.BodyParameter("username", "用户名").DataType("string")).
		Param(ws.BodyParameter("password", "用户密码").DataType("string")))

	ws.Route(ws.GET("/authenticate").
		To(s.wrapRouteFunction(s.ctx.Authenticate)).
		Doc("方法描述：验证").
		Param(ws.HeaderParameter(configs.OAuth2TokenAuthorizationKey, "头部授权信息").DataType("string")))

	ws.Route(ws.DELETE("/token").
		To(s.wrapRouteFunction(s.ctx.Revoke)).
		Doc("方法描述：验证").
		Param(ws.HeaderParameter(configs.OAuth2BasicAuthorizationKey, "头部授权信息").DataType("string")).
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

func (s *RestfulServer) wrapRouteFunction(function func(request *http.Request, response http.ResponseWriter)) restful.RouteFunction {
	return func(request *restful.Request, response *restful.Response) {
		defer func() {
			if err := recover(); err != nil && err != http.ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				s.logger.Errorf("http: panic serving %v: %v\n%s", request.Request.RemoteAddr, err, buf)
				response.WriteErrorString(http.StatusInternalServerError, "内部错误")
			}
		}()

		id := ""
		if s.logHttpInfo {
			id = idUtil.RandomId(32)
			util.LogRequest(id, s.logger.Infof, request)
		}

		function(request.Request, response.ResponseWriter)

		if s.logHttpInfo {
			util.LogResponse(id, s.logger.Infof, response)
		}
	}
}

func (s *RestfulServer) RunWithContainer(wsContainer *restful.Container, host, port string) {
	s.addr = host + ":" + port
	s.ctx.CallbackUrl = s.addr + "/oauth2/authorize/web"
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

	s.Handle(wsContainer)
	defer s.ctx.Close()

	log.Println("start listening on localhost:8080")
	server := &http.Server{Addr: ":" + port, Handler: wsContainer}
	defer server.Close()
	log.Fatal(server.ListenAndServe())
}

func (s *RestfulServer) Run(host, port string) {
	s.RunWithContainer(restful.NewContainer(), host, port)
}

func Run(host, port string) {
	NewRestfulServer(oauth2.New()).Run(host, port)
}
