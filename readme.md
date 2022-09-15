<img src="img.jpg" alt="ep-logo"  width="300"/>

# Ep Auth Service

- [Ep Auth Service](#ep-auth-service)
  - [Generate Token](#generate-token)
  - [Refresh Token](#refresh-token)
 
> **This service is used to validate the user credentials if they are valid then generate a token and then that token will use for rest of the calls**

## EP Auth Service

> **This generate token endpoint is the endpoint that provides a token after validating user-credentials**

**Users**
> There are two users which i have added statically. 

- TelenorAdmin
- TelenorIntern

### Generate Token

`/generate-token`

**Request**
>Content-Type: application/json

**Request**
```json{

{
    "username":"TelenorAdmin",
    "password":"password"
}
```


**Sucess Response**

```json
{
      "access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"	
}
```


**Failure Response**

```json
{
      "statusCode":"01",
      "statusDesc":"Invalid credentials"
}
```
### Refresh Token

`/refresh-token`

**Request**
>Content-Type: application/json

**Request**
Header : {access_token} ( Expired)


**Sucess Response**

```json
{
      "access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"	
}
```


**Failure Response**

```json
{
      "statusCode":"01",
      "statusDesc":"Invalid credentials"
}
```
