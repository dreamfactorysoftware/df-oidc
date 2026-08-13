# df-oidc
OpenID Connect support for DreamFactory


## Overview

DreamFactory is a secure, self-hosted enterprise data access platform that provides governed API access to any data source, connecting enterprise applications and on-prem LLMs with role-based access and identity passthrough.

## Group-to-Role Mapping

An OIDC service can assign a DreamFactory role to a user based on the groups
present in their token, rather than giving every user the same default role.
Because OIDC is a generic protocol, the groups claim varies by provider, so the
claim name is configurable and matching is done on plain string values (group
names *or* ids).

### Configuration

In the OIDC service config (**Services → your OIDC service → Config**):

1. **Map Groups to Roles** — enable the toggle.
2. **Groups Claim Name** — the claim that carries the user's groups. Defaults to
   `groups` (Okta, Keycloak, Azure AD). For Auth0 use your namespaced claim,
   e.g. `https://your-app/groups`.
3. **Group to Role Mapping** — add one row per group: pick a **Role** and enter
   the **Group Name or ID** exactly as it appears in the groups claim. For
   Azure AD via OIDC that is the group's **Object ID (GUID)**; for Okta/Keycloak
   it is the group name.

Groups are read from both the (validated) ID Token and the userinfo response, so
a mapping works whichever source your provider populates.

### Role assignment priority

On every login the user's role assignments are refreshed in this order:

1. **Group mapping** — first group that matches a configured mapping wins.
2. **Role per App** (`app_role_map`) — if no group matched.
3. **Default Role** — fallback when neither of the above applies.

### Provider notes

- **Okta / Keycloak** — add a `groups` scope/claim in the provider so the group
  names are emitted; map on the group name.
- **Auth0** — groups require a namespaced custom claim added via an Action/Rule;
  set *Groups Claim Name* to that URI.
- **Azure AD (via OIDC)** — the `groups` claim contains group **Object IDs
  (GUIDs)**, and Azure only emits it in the **ID Token**. You must therefore
  also enable **Validate ID Token** (with a JWKS URI configured); with
  validation off the ID Token claims are not trusted and no groups are read.
  Add the groups claim under the app registration's **Token configuration**.

### Known limitation: Azure AD groups overage

When a user belongs to more groups than fit in the token (roughly 200+ for
Azure AD), Azure omits the `groups` claim and instead returns a
`_claim_names` / `_claim_sources` pointer to the Microsoft Graph API. Resolving
the full group list would require a separate Graph directory call, which this
package does not perform. In that case group-to-role mapping is skipped (a
warning is logged) and the user falls back to the default role. If you have
users in very large numbers of groups, keep the mapped groups within Azure's
token limit (e.g. via a groups-claim filter on the app registration) so the
relevant groups are emitted directly in the token.
