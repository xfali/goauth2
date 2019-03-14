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
    "io"
    "log"
    "net/http"
    "oauth2/defines"
    "oauth2/utils"
)

type OAuth2 struct {
    ClientCreator func() defines.ClientInfo
}

func New() *OAuth2 {
    return &OAuth2{
        utils.DefaultClientGenerator,
    }
}

func (auth *OAuth2) RegisterTo(c *restful.Container) {
    ws := new(restful.WebService)
    //设置匹配的schema和路径
    ws.Path("/auth").Consumes("*/*").Produces("*/*")

    //设置不同method对应的方法，参数以及参数描述和类型
    //参数:分为路径上的参数,query层面的参数,Header中的参数
    ws.Route(ws.GET("").
        To(auth.auth).
        Doc("方法描述：验证").
        Param(ws.QueryParameter("response_type", "应答类型").DataType("string")).
        Param(ws.QueryParameter("client_id", "client_id").DataType("string")).
        Param(ws.QueryParameter("redirect_uri", "重定向地址").DataType("string")).
        Param(ws.QueryParameter("scope", "授权范围").DataType("string")).
        Param(ws.QueryParameter("state", "状态").DataType("string")))

    ws.Route(ws.POST("").
        To(auth.register).
        Doc("方法描述：增加用户"))

    c.Add(ws)
}

func (auth *OAuth2) auth(request *restful.Request, response *restful.Response) {
    response_type := request.QueryParameter("response_type")
    client_id := request.QueryParameter("client_id")
    redirect_uri := request.QueryParameter("redirect_uri")
    scope := request.QueryParameter("scope")
    state := request.QueryParameter("state")
    log.Printf("response_type: %s client_id: %s redirect_uri: %s scope: %s state: %s\n", response_type, client_id, redirect_uri, scope, state)

    io.WriteString(response.ResponseWriter, "this would be a normal response")
}

func (auth *OAuth2) register(request *restful.Request, response *restful.Response) {
    clientInfo := auth.ClientCreator()
    b, err := json.Marshal(clientInfo)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    response.Write(b)
}
