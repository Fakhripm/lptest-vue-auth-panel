# Changelog

## 1.1.0

- Refresh tokens on login/register (`typ: refresh`, longer-lived)
- `POST /auth/refresh` and stateless `POST /auth/logout`
- `GET /auth/me` includes `iat` / `exp`
- Remember-me: `remember: true` → access token 30d, else 1d
- CI workflow and project docs

## 1.0.0

- Vue login/register + Node JWT API
