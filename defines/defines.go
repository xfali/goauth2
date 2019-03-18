/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package defines

import "time"

type ClientInfo struct {
    ClientId     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
}

type ClientManager interface {
    CreateClient() (ClientInfo, error)
    QuerySecret(string) (string, error)
    UpdateClient(string) (string, error)
    DeleteClient(string) error
}

type DataManager interface {
    Set(key ,value string, duration time.Duration) error
    Get(key string) string
    Close()
}