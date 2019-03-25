package defines

import (
    "fmt"
    "net/http"
)

//const(
//    CODE_IS_MISSING = 1
//    CODE_IS_INVALID = 2
//    CLINET_ID_MISSING = 3
//)

var INTERNAL_ERROR *ErrCode = NewErrCode("1000", "internal error")
var SAVE_DATA_ERROR *ErrCode = NewErrCode("1001", "save data error")
var CODE_IS_MISSING *ErrCode = NewErrCode("1101", "code is missing")
var CODE_IS_INVALID *ErrCode = NewErrCode("1102", "check code error")
var CLINET_ID_MISSING *ErrCode = NewErrCode("1103", "client_id is missing")
var CLINET_ID_NOT_MATCH *ErrCode = NewErrCode("1104", "client_id is Not match")
var CLIENT_SECRET_MISSING *ErrCode = NewErrCode("1105", "client_secret is missing")
var CHECK_CLIENT_ID_ERROR *ErrCode = NewErrCode("1106", "Check client_id error")
var CLINET_SECRET_NOT_MATCH *ErrCode = NewErrCode("1107", "client_secret is Not match")
var REDIRECT_URI_MISSING *ErrCode = NewErrCode("1108", "redirect_uri is missing")
var PASSWORD_CREDENTIALS_HEAD_MISSING *ErrCode = NewErrCode("1111", "Password Credentials Header: Authorization missing")
var USERNAME_MISSING *ErrCode = NewErrCode("1112", "username is missing")
var PASSWORD_MISSING *ErrCode = NewErrCode("1113", "password is missing")
var PASSWORD_NOT_MATCH *ErrCode = NewErrCode("1114", "password is not match")
var AUTHORIZATION_BASIC_ERROR *ErrCode = NewErrCode("1115", "authorization basic error")
var REFRESH_TOKEN_MISSING *ErrCode = NewErrCode("1116", "refresh token is missing")
var REFRESH_TOKEN_NOT_FOUND *ErrCode = NewErrCode("1117", "refresh token not found")
var ACCESSTOKEN_MISSING *ErrCode = NewErrCode("2000", "Access token: Authorization missing")
var GENERATE_ACCESSTOKEN_ERROR *ErrCode = NewErrCode("2001", "generate access token error")
var GENERATE_REFRESHTOKEN_ERROR *ErrCode = NewErrCode("2002", "generate refresh token error")
var AUTHENTICATE_ACCESSTOKEN_ERROR *ErrCode = NewErrCode("2010", "authenticate access token error")
var TOKEN_ERROR *ErrCode = NewErrCode("2003", "解析Token发生错误")

type ErrCode struct {
    Code       string `json:"code"`
    Msg        string `json:"msg"`
    HttpStatus int

    jsonStr string
}

func NewErrCode(code string, msg string) *ErrCode {
    return &ErrCode{code, msg, http.StatusOK,fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", code, msg)}
}

func NewErrCodeWithHttpStatus(code string, msg string, httpstatus int) *ErrCode {
    return &ErrCode{code, msg, httpstatus,fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", code, msg)}
}

func (errcode *ErrCode) format() *ErrCode {
    if errcode.jsonStr == "" {
        errcode.jsonStr = fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", errcode.Code, errcode.Msg)
    }
    return errcode
}

func (errcode *ErrCode) Error() string {
    return errcode.format().jsonStr
}
