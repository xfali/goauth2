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

func (errcode *ErrCode) Format() *ErrCode {
    if errcode.jsonStr == "" {
        errcode.jsonStr = fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", errcode.Code, errcode.Msg)
    }
    return errcode
}

func (errcode *ErrCode) Error() string {
    return errcode.jsonStr
}
