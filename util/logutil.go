package util

import (
	"time"
	"github.com/emicklei/go-restful"
)

type LogFunc func(format string, args ...interface{})

func LogRequest(id string, logFunc LogFunc, request *restful.Request) {
	logFunc(
		"Request id: %s at: %v RemoteAddr: %s Method: %s RequestURI: %s Header: %v\n",
		id,
		time.Now(),
		request.Request.RemoteAddr, // 客户端 IP 和端口
		request.Request.Method,     // 请求方法
		request.Request.RequestURI, // 请求 URI 路径
		request.Request.Header,     // 请求头
		 )
}

func LogResponse(id string, logFunc LogFunc, response *restful.Response) {
	logFunc(
		"Response id: %s at: %v StatusCode: %d ContentLength: %d Header: %v\n",
		id,
		time.Now(),
		response.StatusCode(), // 客户端 IP 和端口
		response.ContentLength(),     // 请求方法
		response.Header(),     // 请求头
	)
}
