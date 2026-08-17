# ConnectHub Test Client

A minimal Node.js OIDC client application used to test
ConnectHub Lightweight Identity Federation Layer.

## Architecture

SaaS Application
        |
        v
ConnectHub
        |
   +----+----+
   |    |    |
 Entra Okta Keycloak

## Running

```bash
npm install
node app.js