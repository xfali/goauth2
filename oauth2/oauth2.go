/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package oauth2

import (
	"encoding/json"
	"github.com/emicklei/go-restful"
	"github.com/xfali/goid"
	"io"
	"log"
	"net/http"
	"oauth2/buildin"
	"oauth2/defines"
	"oauth2/util"
	"runtime"
	"strings"
	"time"
)

const (
	RESPONSE_TYPE_CODE = "code"
	CODE_EXPIRE_TIME   = 10 * time.Minute
)

type OAuth2 struct {
	ClientManager  defines.ClientManager
	DataManager    defines.DataManager
	CodeExpireTime time.Duration
	ErrorLog       *log.Logger
	LogHttpInfo    bool
}

func New() *OAuth2 {
	return &OAuth2{
		ClientManager: buildin.NewDefaultClientManager(),
		DataManager:   buildin.NewDefaultDataManager(0),
		CodeExpireTime: CODE_EXPIRE_TIME,
		LogHttpInfo:   true,
	}
}

func (auth *OAuth2) Close() {
	auth.DataManager.Close()
}

func (auth *OAuth2) RegisterTo(c *restful.Container) {
	ws := new(restful.WebService)
	//设置匹配的schema和路径
	ws.Path("/auth").Consumes("*/*").Produces("*/*")

	//设置不同method对应的方法，参数以及参数描述和类型
	//参数:分为路径上的参数,query层面的参数,Header中的参数
	ws.Route(ws.GET("").
		To(auth.wrapRouteFunction(auth.auth)).
		Doc("方法描述：验证").
		Param(ws.QueryParameter("response_type", "应答类型").DataType("string")).
		Param(ws.QueryParameter("client_id", "client_id").DataType("string")).
		Param(ws.QueryParameter("redirect_uri", "重定向地址").DataType("string")).
		Param(ws.QueryParameter("scope", "授权范围").DataType("string")).
		Param(ws.QueryParameter("state", "状态").DataType("string")))

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

	c.Add(ws)
}

func (auth *OAuth2) auth(request *restful.Request, response *restful.Response) {
	response_type := request.QueryParameter("response_type")
	client_id := request.QueryParameter("client_id")
	redirect_uri := request.QueryParameter("redirect_uri")
	scope := request.QueryParameter("scope")
	state := request.QueryParameter("state")
	log.Printf("response_type: %s client_id: %s redirect_uri: %s scope: %s state: %s\n", response_type, client_id, redirect_uri, scope, state)

	switch response_type {
	case RESPONSE_TYPE_CODE:
		param := map[string]string{}
		param["state"] = state
		auth.processAuthorizationCode(client_id, redirect_uri, param, request, response)
		return
	}

	io.WriteString(response.ResponseWriter, "this would be a normal response")
}

func (auth *OAuth2) processAuthorizationCode(client_id, redirect_uri string, param map[string]string, request *restful.Request, response *restful.Response) {
	code := goid.RandomId(30)
	auth.DataManager.Set(code, client_id, auth.CodeExpireTime)
	param["code"] = code
	redirect_uri = addParam(redirect_uri, param)
	http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}

func addParam(url string, param map[string]string) string {
	if strings.LastIndex(url, "?") != -1 {
		url += "?"
	}

	size := len(param)
	for k, v := range param {
		url += k + "=" + v
		size--
		if size != 0 {
			url += "&"
		}
	}

	return url
}

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

func (auth *OAuth2) wrapRouteFunction(function restful.RouteFunction) restful.RouteFunction {
	return func(request *restful.Request, response *restful.Response) {
		defer func() {
			if err := recover(); err != nil && err != http.ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				auth.logf("http: panic serving %v: %v\n%s", request.Request.RemoteAddr, err, buf)
				response.WriteErrorString(http.StatusInternalServerError, "内部错误")
			}
		}()

		id := ""
		if auth.LogHttpInfo {
			id = goid.RandomId(32)
			util.LogRequest(id, auth.logf, request)
		}

		function(request, response)

		if auth.LogHttpInfo {
			util.LogResponse(id, auth.logf, response)
		}
	}
}

func (auth *OAuth2) logf(format string, args ...interface{}) {
	if auth.ErrorLog != nil {
		auth.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
