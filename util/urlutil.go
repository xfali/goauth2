/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package util

import "strings"

func AddParam(url string, param map[string]string) string {
    if strings.LastIndex(url, "?") != -1 {
        url += "?"
    }

    size := len(param)
    for k, v := range param {
        url += k + "=" + v
        size--
        if size != 0 {
            url += "&"
        }
    }

    return url
}
