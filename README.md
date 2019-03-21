# oauth2
go语言实现的oauth2.0

## The Authorization Code Flow

### Get the User’s Permission

```
https://authorization-server.com/auth
 ?response_type=code
 &client_id=29352915982374239857
 &redirect_uri=https%3A%2F%2Fexample-app.com%2Fcallback
 &scope=create+delete
 &state=xcoiv98y2kd22vusuye3kch
```
### Redirect Back to the Application

```
https://example-app.com/redirect
 ?code=g0ZGZmNjVmOWIjNTk2NTk4ZTYyZGI3
 &state=xcoiv98y2kd22vusuye3kch
```

### Exchange the Authorization Code for an Access Token

```
POST /oauth/token HTTP/1.1
Host: authorization-server.com
Content-type: application/x-www-form-urlencoded

response_type=code
&client_id=29352915982374239857
&redirect_uri=https%3A%2F%2Fexample-app.com%2Fcallback
&scope=create+delete
&state=xcoiv98y2kd22vusuye3kch
```

## OAuth 2.0 Password Grant

```
POST /oauth/token HTTP/1.1
Host: authorization-server.com
Content-type: application/x-www-form-urlencoded

grant_type=password
&username=exampleuser
&password=1234luggage
&client_id=xxxxxxxxxx

```

## Client Credentials

```
POST /token HTTP/1.1
Host: authorization-server.com

grant_type=client_credentials
&client_id=xxxxxxxxxx
&client_secret=xxxxxxxxxx
```

## Refresh Token

```
POST /oauth/token HTTP/1.1
Host: authorization-server.com

grant_type=refresh_token
&refresh_token=xxxxxxxxxxx
&client_id=xxxxxxxxxx
&client_secret=xxxxxxxxxx
```