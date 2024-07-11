package errcodes

import (
	"fmt"
	"net/http"
)

//const(
//    CODE_IS_MISSING = 1
//    CODE_IS_INVALID = 2
//    CLINET_ID_MISSING = 3
//)

var InternalError *ErrCode = NewErrCodeWithHttpStatus("1000", "internal error", http.StatusInternalServerError)
var SaveDataError *ErrCode = NewErrCodeWithHttpStatus("1001", "save data error", http.StatusInternalServerError)
var CodeIsMissing *ErrCode = NewErrCodeWithHttpStatus("1101", "code is missing", http.StatusUnauthorized)
var CodeIsInvalid *ErrCode = NewErrCodeWithHttpStatus("1102", "check code error", http.StatusUnauthorized)
var ClientIdMissing *ErrCode = NewErrCodeWithHttpStatus("1103", "client_id is missing", http.StatusUnauthorized)
var ClientIdNotMatch *ErrCode = NewErrCodeWithHttpStatus("1104", "client_id is Not match", http.StatusUnauthorized)
var ClientSecretMissing *ErrCode = NewErrCodeWithHttpStatus("1105", "client_secret is missing", http.StatusUnauthorized)
var CheckClientIdError *ErrCode = NewErrCodeWithHttpStatus("1106", "Check client_id error", http.StatusUnauthorized)
var ClientSecretNotMatch *ErrCode = NewErrCodeWithHttpStatus("1107", "client_secret is Not match", http.StatusUnauthorized)
var RedirectUriMissing *ErrCode = NewErrCodeWithHttpStatus("1108", "redirect_uri is missing", http.StatusUnauthorized)
var ScopeMissing *ErrCode = NewErrCodeWithHttpStatus("1109", "scope is missing", http.StatusUnauthorized)
var ScopeError *ErrCode = NewErrCodeWithHttpStatus("1110", "scope error", http.StatusUnauthorized)
var PasswordCredentialsHeadMissing *ErrCode = NewErrCodeWithHttpStatus("1111", "Password Credentials Header: Authorization missing", http.StatusUnauthorized)
var UsernameMissing *ErrCode = NewErrCodeWithHttpStatus("1112", "username is missing", http.StatusUnauthorized)
var PasswordMissing *ErrCode = NewErrCodeWithHttpStatus("1113", "password is missing", http.StatusUnauthorized)
var PasswordNotMatch *ErrCode = NewErrCodeWithHttpStatus("1114", "password is not match", http.StatusUnauthorized)
var AuthorizationBasicError *ErrCode = NewErrCodeWithHttpStatus("1115", "authorization basic error", http.StatusUnauthorized)
var RefreshTokenMissing *ErrCode = NewErrCodeWithHttpStatus("1116", "refresh token is missing", http.StatusUnauthorized)
var RefreshTokenNotFound *ErrCode = NewErrCodeWithHttpStatus("1117", "refresh token not found", http.StatusUnauthorized)
var UserAuthorizeCheckError *ErrCode = NewErrCodeWithHttpStatus("1118", "check user authorize error", http.StatusUnauthorized)
var ResponseTypeNotSupport *ErrCode = NewErrCodeWithHttpStatus("1201", "response type not support", http.StatusBadRequest)
var AccessTokenMissing *ErrCode = NewErrCodeWithHttpStatus("2000", "Access token: Authorization missing", http.StatusUnauthorized)
var GenerateAccessTokenError *ErrCode = NewErrCodeWithHttpStatus("2001", "generate access token error", http.StatusInternalServerError)
var GenerateRefreshTokenError *ErrCode = NewErrCodeWithHttpStatus("2002", "generate refresh token error", http.StatusInternalServerError)
var SaveAccessTokenError *ErrCode = NewErrCodeWithHttpStatus("2011", "save access token error", http.StatusInternalServerError)
var SaveRefreshTokenError *ErrCode = NewErrCodeWithHttpStatus("2012", "save refresh token error", http.StatusInternalServerError)
var AuthenticateAccessTokenError *ErrCode = NewErrCodeWithHttpStatus("2021", "authenticate access token error", http.StatusUnauthorized)
var TokenError *ErrCode = NewErrCodeWithHttpStatus("2023", "解析Token发生错误", http.StatusUnauthorized)
var GrantTypeMissing *ErrCode = NewErrCodeWithHttpStatus("3001", "grant type missing", http.StatusBadRequest)
var GrantTypeNotSupport *ErrCode = NewErrCodeWithHttpStatus("3002", "grant type not support", http.StatusBadRequest)

type ErrCode struct {
	Code       string `json:"code"`
	Msg        string `json:"msg"`
	HttpStatus int

	jsonStr string
}

func NewErrCode(code string, msg string) *ErrCode {
	return &ErrCode{code, msg, http.StatusUnauthorized, fmt.Sprintf(`{ "code" : "%s", "msg" : "%s" }`, code, msg)}
}

func NewErrCodeWithHttpStatus(code string, msg string, httpstatus int) *ErrCode {
	return &ErrCode{code, msg, httpstatus, fmt.Sprintf(`{ "code" : "%s", "msg" : "%s" }`, code, msg)}
}

func (errcode *ErrCode) format() *ErrCode {
	if errcode.jsonStr == "" {
		errcode.jsonStr = fmt.Sprintf(`{ "code" : "%s", "msg" : "%s" }`, errcode.Code, errcode.Msg)
	}
	return errcode
}

func (errcode *ErrCode) Error() string {
	return errcode.format().jsonStr
}
