package defines

import "fmt"

//const(
//    CODE_IS_MISSING = 1
//    CODE_IS_INVALID = 2
//    CLINET_ID_MISSING = 3
//)

var INTERNAL_ERROR ErrCode = ErrCode{ "1000", "internal error" }
var CODE_IS_MISSING ErrCode = ErrCode{ "1001", "code is missing" }
var CODE_IS_INVALID ErrCode = ErrCode{ "1002", "code is invalid" }
var CLINET_ID_MISSING ErrCode = ErrCode{ "1003", "client_id is missing" }
var CLINET_ID_NOT_MATCH ErrCode = ErrCode{ "1004", "client_id is Not match" }
var CLIENT_SECRET_MISSING ErrCode = ErrCode{ "1005", "client_secret is missing" }
var CHECK_CLIENT_ID_ERROR ErrCode = ErrCode{ "1006", "Check client_id error" }
var CLINET_SECRET_NOT_MATCH ErrCode = ErrCode{ "1007", "client_secret is Not match" }


type ErrCode struct {
    code string `json:"code"`
    msg string `json:"msg"`
}

func NewErrCode(code string, msg string) *ErrCode {
    return &ErrCode{code, msg}
}

func (errcode *ErrCode) Error() string{
    return fmt.Sprintf("{ \"code\" : %s, \"msg\" : %s }", errcode.code, errcode.msg)
}

