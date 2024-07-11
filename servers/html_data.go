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

package servers

var (
	LoginHtml = `<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
</head>

<style>
    .login-container {
        margin: 50px;
        width: 100%;
    }

    .form-container {
        margin: 0px auto;
        width: 50%;
        text-align: center;
        box-shadow: 1px 1px 10px #888888;
        height: 300px;
        padding: 5px;
    }

    input {
        margin-top: 10px;
        width: 350px;
        height: 30px;
        border-radius: 3px;
        border: 1px #E9686B solid;
        padding-left: 2px;

    }


    .btn {
        width: 350px;
        height: 35px;
        line-height: 35px;
        cursor: pointer;
        margin-top: 20px;
        border-radius: 3px;
        background-color: #E9686B;
        color: white;
        border: none;
        font-size: 15px;
    }

    .title {
        margin-top: 5px;
        font-size: 18px;
        color: #E9686B;
    }
</style>
<body>
<div class="login-container">
    <div class="form-container">
        <p class="title">用户登录</p>
        <form name="loginForm" method="post" action="LOGIN_API_PATH">
            <input type="text" name="username" placeholder="用户名"/>
            <br>
            <input type="password" name="password" placeholder="密码"/>
            <br>
            <button type="submit" class="btn">登 &nbsp;&nbsp; 录</button>
        </form>
    </div>
</div>
</body>
</html>`
	AuthorizeHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>授权</title>
</head>
<style>

    html {
        padding: 0px;
        margin: 0px;
    }

    .title {
        background-color: #E9686B;
        height: 50px;
        padding-left: 20%;
        padding-right: 20%;
        color: white;
        line-height: 50px;
        font-size: 18px;
    }

    .title-left {
        float: right;
    }

    .title-right {
        float: left;
    }

    .title-left a {
        color: white;
    }

    .container {
        clear: both;
        text-align: center;
    }

    .btn {
        width: 350px;
        height: 35px;
        line-height: 35px;
        cursor: pointer;
        margin-top: 20px;
        border-radius: 3px;
        background-color: #E9686B;
        color: white;
        border: none;
        font-size: 15px;
    }
</style>
<body style="margin: 0px">
<div class="title">
    <div align="center">xfali OAUTH2</div>
    <!--
    <div class="title-right">xfali OAUTH2</div>
    <div class="title-left">
        <a href="#help">帮助</a>
    </div>
    -->
</div>
<div class="container">
    <h3 text="请求授权，该应用将获取你的以下信息'"></h3>
    <p>昵称，头像和性别</p>
    授权后表明你已同意 <a href="#boot" style="color: #E9686B">xfali OAUTH2 服务协议</a>
    <form method="post" action="AUTHORIZE_API_PATH">
        <button class="btn" type="submit"> 同意/授权</button>
    </form>
</div>
</body>
</html>
`
)
