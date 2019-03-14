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
    "oauth2/buildin"
)

type OAuth2 struct {
    cm defines.ClientManager
}

func New() *OAuth2 {
    return &OAuth2{
        cm: buildin.NewDefaultClientManager(),
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

    //for test
    ws.Route(ws.POST("/client").
        To(auth.createClient).
        Doc("方法描述：增加client"))
    ws.Route(ws.PUT("/client").
        To(auth.updateClient).
        Doc("方法描述：更新密钥").
        Param(ws.BodyParameter("client_id", "client_id").DataType("string")))
    ws.Route(ws.DELETE("/client").
        To(auth.deleteClient).
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

    io.WriteString(response.ResponseWriter, "this would be a normal response")
}

func (auth *OAuth2) createClient(request *restful.Request, response *restful.Response) {
    clientInfo, err := auth.cm.CreateClient()
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
    secret, err := auth.cm.UpdateClient(client_id)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    io.WriteString(response.ResponseWriter, secret)
}

func (auth *OAuth2) deleteClient(request *restful.Request, response *restful.Response) {
    client_id := request.PathParameter("client_id")
    err := auth.cm.DeleteClient(client_id)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    response.WriteHeader(http.StatusOK)
}
