# Security testing example

This example project shows an issue with testing the security configuration after upgrading to
Spring Boot 4 without properly updating the (test) dependencies.

Separate commits are used to illustrate different setups:

- Spring Boot 3 → tests succeed
- Spring Boot 4 without fully adjusted test dependencies → tests fail
- Spring Boot 4 with fully adjusted test dependencies → tests succeed

## Running the application

To run the application:

```shell
mvn clean spring-boot:run
```

You can then use e.g. cURL to query it. Here are some examples:

### Get user token

Retrieve a fresh user token with:

```shell
curl --fail --location 'localhost:8080/getUserToken'
```

The output is a Bearer token with `User` authority. E.g. `Bearer ey…`

### Get admin token

Similarly, retrieve a fresh admin token with:

```shell
curl --fail --location 'localhost:8080/getAdminToken'
```

The output is a Bearer token with `Admin` authority. E.g. `Bearer ey…`

### Get user info

```shell
curl --fail --location 'localhost:8080/getUserInfo' --header 'Authorization: Bearer ey…'
```

Fill in the user or admin token retrieved earlier. This should result in the output
`User Information[<name>]`, with `<name>` either `User` or `Admin`, depending on the token used.

### Get admin info

```shell
curl --fail --location 'localhost:8080/getUserInfo' --header 'Authorization: Bearer ey…'
```

Fill in the user or admin token retrieved earlier. This should result in the output
`Admin Information[Admin]` when using the Admin token, or fail with a 403 error when using the User
token.
