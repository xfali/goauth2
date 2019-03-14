/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package utils

import (
    "github.com/xfali/goid"
    "oauth2/defines"
)

var GlobalId *goid.SnowFlake = goid.NewSnowFlake()

func DefaultClientGenerator() defines.ClientInfo {
    id, _ := GlobalId.NextId()
    return defines.ClientInfo{
        ClientId: id.Compress().String(),
        ClientSecret: goid.RandomId(32),
    }
}
