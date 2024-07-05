/*
 * Copyright (C) 2019-2024, Xiongfa Li.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package util

import "strings"

func AddParam(url string, param map[string]string) string {
	if strings.LastIndex(url, "?") == -1 {
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

func AddFragment(url string, fragmentKey string, fragmentValue string) string {
	kv := ""
	if fragmentValue != "" {
		kv = "="
	}
	return url + "#" + fragmentKey + kv + fragmentValue
}
