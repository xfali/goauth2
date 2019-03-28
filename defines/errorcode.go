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

var INTERNAL_ERROR *ErrCode = NewErrCodeWithHttpStatus("1000", "internal error", http.StatusInternalServerError)
var SAVE_DATA_ERROR *ErrCode = NewErrCodeWithHttpStatus("1001", "save data error", http.StatusInternalServerError)
var CODE_IS_MISSING *ErrCode = NewErrCodeWithHttpStatus("1101", "code is missing", http.StatusUnauthorized)
var CODE_IS_INVALID *ErrCode = NewErrCodeWithHttpStatus("1102", "check code error", http.StatusUnauthorized)
var CLINET_ID_MISSING *ErrCode = NewErrCodeWithHttpStatus("1103", "client_id is missing", http.StatusUnauthorized)
var CLINET_ID_NOT_MATCH *ErrCode = NewErrCodeWithHttpStatus("1104", "client_id is Not match", http.StatusUnauthorized)
var CLIENT_SECRET_MISSING *ErrCode = NewErrCodeWithHttpStatus("1105", "client_secret is missing", http.StatusUnauthorized)
var CHECK_CLIENT_ID_ERROR *ErrCode = NewErrCodeWithHttpStatus("1106", "Check client_id error", http.StatusUnauthorized)
var CLINET_SECRET_NOT_MATCH *ErrCode = NewErrCodeWithHttpStatus("1107", "client_secret is Not match", http.StatusUnauthorized)
var REDIRECT_URI_MISSING *ErrCode = NewErrCodeWithHttpStatus("1108", "redirect_uri is missing", http.StatusUnauthorized)
var SCOPE_MISSING *ErrCode = NewErrCodeWithHttpStatus("1109", "scope is missing", http.StatusUnauthorized)
var SCOPE_ERROR *ErrCode = NewErrCodeWithHttpStatus("1110", "scope error", http.StatusUnauthorized)
var PASSWORD_CREDENTIALS_HEAD_MISSING *ErrCode = NewErrCodeWithHttpStatus("1111", "Password Credentials Header: Authorization missing", http.StatusUnauthorized)
var USERNAME_MISSING *ErrCode = NewErrCodeWithHttpStatus("1112", "username is missing", http.StatusUnauthorized)
var PASSWORD_MISSING *ErrCode = NewErrCodeWithHttpStatus("1113", "password is missing", http.StatusUnauthorized)
var PASSWORD_NOT_MATCH *ErrCode = NewErrCodeWithHttpStatus("1114", "password is not match", http.StatusUnauthorized)
var AUTHORIZATION_BASIC_ERROR *ErrCode = NewErrCodeWithHttpStatus("1115", "authorization basic error", http.StatusUnauthorized)
var REFRESH_TOKEN_MISSING *ErrCode = NewErrCodeWithHttpStatus("1116", "refresh token is missing", http.StatusUnauthorized)
var REFRESH_TOKEN_NOT_FOUND *ErrCode = NewErrCodeWithHttpStatus("1117", "refresh token not found", http.StatusUnauthorized)
var USERAUTHORIZE_CHECK_ERROR *ErrCode = NewErrCodeWithHttpStatus("1118", "check user authorize error", http.StatusUnauthorized)
var RESPONSE_TYPE_NOT_SUPPORT *ErrCode = NewErrCodeWithHttpStatus("1201", "response type not support", http.StatusBadRequest)
var ACCESSTOKEN_MISSING *ErrCode = NewErrCodeWithHttpStatus("2000", "Access token: Authorization missing", http.StatusUnauthorized)
var GENERATE_ACCESSTOKEN_ERROR *ErrCode = NewErrCodeWithHttpStatus("2001", "generate access token error", http.StatusInternalServerError)
var GENERATE_REFRESHTOKEN_ERROR *ErrCode = NewErrCodeWithHttpStatus("2002", "generate refresh token error", http.StatusInternalServerError)
var SAVE_ACCESSTOKEN_ERROR *ErrCode = NewErrCodeWithHttpStatus("2001", "save access token error", http.StatusInternalServerError)
var SAVE_REFRESHTOKEN_ERROR *ErrCode = NewErrCodeWithHttpStatus("2002", "save refresh token error", http.StatusInternalServerError)
var AUTHENTICATE_ACCESSTOKEN_ERROR *ErrCode = NewErrCodeWithHttpStatus("2010", "authenticate access token error", http.StatusUnauthorized)
var TOKEN_ERROR *ErrCode = NewErrCodeWithHttpStatus("2003", "解析Token发生错误", http.StatusUnauthorized)

type ErrCode struct {
    Code       string `json:"code"`
    Msg        string `json:"msg"`
    HttpStatus int

    jsonStr string
}

func NewErrCode(code string, msg string) *ErrCode {
    return &ErrCode{code, msg, http.StatusUnauthorized, fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", code, msg)}
}

func NewErrCodeWithHttpStatus(code string, msg string, httpstatus int) *ErrCode {
    return &ErrCode{code, msg, httpstatus, fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", code, msg)}
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
