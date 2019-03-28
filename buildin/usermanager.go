/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description:
 */

package buildin

import (
    "github.com/xfali/oauth2/defines"
    "net/http"
)

type DefaultUserManager struct {
    db           map[string]string
    loginUrl     string
    authorizeUrl string
}

func NewDefaultUserManager(loginUrl, authorizeUrl string) *DefaultUserManager {
    ret := &DefaultUserManager{db: map[string]string{}, loginUrl: loginUrl, authorizeUrl: authorizeUrl}
    return ret
}

func (um *DefaultUserManager) CheckUser(username, password string) error {
    if um.db[username] == password {
        return nil
    } else {
        return defines.PASSWORD_NOT_MATCH
    }
}

func (um *DefaultUserManager) CreateUser(username, password string) error {
    um.db[username] = password
    return nil
}

func (um *DefaultUserManager) UserAuthorize(r *http.Request) (string, error) {
    _, err := r.Cookie("JSESSIONID")
    if err != nil {
        return um.loginUrl, nil
    } else {
        return um.authorizeUrl, nil
    }
}
