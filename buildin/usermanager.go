/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description:
 */

package buildin

import "github.com/xfali/oauth2/defines"

type DefaultUserManager map[string]string

func NewDefaultUserManager() *DefaultUserManager {
    ret := &DefaultUserManager{}
    return ret
}

func (um *DefaultUserManager) CheckUser(username, password string) error {
    if (*um)[username] == password {
        return nil
    } else {
        return defines.PASSWORD_NOT_MATCH
    }
}

func (um *DefaultUserManager) CreateUser(username, password string) error {
    (*um)[username] = password
    return nil
}