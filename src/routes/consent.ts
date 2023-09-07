// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import express from "express"
import url from "url"
import csrf from "csurf"
import { hydraAdmin } from "../config"
import { OAuth2ConsentRequest } from "@ory/client"

const csrfProtection = csrf({ cookie: { sameSite: "lax" } })
const router = express.Router()

router.get("/", csrfProtection, (req, res, next) => {

  const query = url.parse(req.url, true).query

  // The challenge is used to fetch information about the consent request from ORY hydraAdmin.
  const challenge = String(query.consent_challenge)

  if (!challenge) {
    next(new Error("Expected a consent challenge to be set but received none."))
    return
  }

  // Just accept the consent request because we control both ends.
  //
  // The client is always trusted and first-party therefore we don't need the content form. See:
  //   https://www.ory.sh/docs/oauth2-oidc/custom-login-consent/flow#skipping-consent-for-trusted-clients
  //
  hydraAdmin.adminGetOAuth2ConsentRequest(challenge).then(({ data: body }) => {
    return hydraAdmin.adminAcceptOAuth2ConsentRequest(challenge, consentParams(body)).then(({ data: body }) => {
      res.redirect(String(body.redirect_to))
    })
  }).catch(next)
})

function consentParams(body: OAuth2ConsentRequest) {
  return {
    grant_scope: body.requested_scope,
    grant_access_token_audience: body.requested_access_token_audience,
    remember: true,
    remember_for: 3600,

    // The session allows us to set session data for id and access tokens
    // AVOID sensitive information here.
    // session: {
    //   access_token: { foo: 'bar' },      // This data will be available when introspecting the token.
    //   id_token: { baz: 'bar' }           // This data will be available in the ID token.
    // }
  }
}


export default router
