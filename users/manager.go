/*
 * Copyright (C) 2024, Xiongfa Li.
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

package users

import "net/http"

type UserManager interface {
	//验证用户名和密码
	CheckUser(username, password string) error

	//当类型为网页授权时，调用该方法检测用户是否登录
	//返回重定向授权页面的地址
	UserAuthorize(r *http.Request) (string, error)
}
