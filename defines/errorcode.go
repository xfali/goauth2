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
var CODE_IS_MISSING *ErrCode = NewErrCode("1001", "code is missing")
var CODE_IS_INVALID *ErrCode = NewErrCode("1002", "code is invalid")
var CLINET_ID_MISSING *ErrCode = NewErrCode("1003", "client_id is missing")
var CLINET_ID_NOT_MATCH *ErrCode = NewErrCode("1004", "client_id is Not match")
var CLIENT_SECRET_MISSING *ErrCode = NewErrCode("1005", "client_secret is missing")
var CHECK_CLIENT_ID_ERROR *ErrCode = NewErrCode("1006", "Check client_id error")
var CLINET_SECRET_NOT_MATCH *ErrCode = NewErrCode("1007", "client_secret is Not match")
var REDIRECT_URI_MISSING *ErrCode = NewErrCode("1008", "redirect_uri is missing")
var PASSWORD_CREDENTIALS_HEAD_MISSING *ErrCode = NewErrCode("1011", "Password Credentials Header: Authorization missing")
var USERNAME_MISSING *ErrCode = NewErrCode("1012", "username is missing")
var PASSWORD_MISSING *ErrCode = NewErrCode("1013", "password is missing")
var PASSWORD_NOT_MATCH *ErrCode = NewErrCode("1014", "password is not match")
var AUTHORIZATION_BASIC_ERROR *ErrCode = NewErrCode("1015", "authorization basic error")
var REFRESH_TOKEN_MISSING *ErrCode = NewErrCode("1016", "refresh token is missing")
var REFRESH_TOKEN_NOT_FOUND *ErrCode = NewErrCode("1017", "refresh token not found")
var GENERATE_ACCESSTOKEN_ERROR *ErrCode = NewErrCode("2001", "generate access token error")
var GENERATE_REFRESHTOKEN_ERROR *ErrCode = NewErrCode("2002", "generate refresh token error")
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
