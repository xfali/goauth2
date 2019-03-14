/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package main

import (
    "github.com/emicklei/go-restful"
    "log"
    "net/http"
    "oauth2/oauth2"
)

func main(){
    wsContainer := restful.NewContainer()

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


    u := oauth2.New()
    u.RegisterTo(wsContainer)

    log.Println("start listening on localhost:8080")
    server := &http.Server{Addr: ":8080", Handler: wsContainer}
    defer server.Close()
    log.Fatal(server.ListenAndServe())
}
