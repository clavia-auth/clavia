# Paging and search

## Pages

A list that can grow without bound answers one page at a time:

```bash
curl -s 'https://management.example.com/api/v1/users?page=2&per_page=2' \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "items": [
    {"id": "0ce5e83d-dc05-4a31-a869-4eba42aaab18", "email": "ada@example.com", "…": "…"}
  ],
  "total": 3,
  "page": 2,
  "per_page": 2
}
```

| Parameter | Default | Range |
|---|---|---|
| `page` | `1` | from 1 |
| `per_page` | `50` | 1 to 100 |

- **`total`** counts every item matching the request, across all pages.
- **Lists are newest first.**
- **A page past the end is not an error.** It comes back with no `items` and the same `total`.
- **Out of range is refused, not adjusted.** `per_page=500` is `422`, never quietly cut to 100.

To read everything, ask for pages until `page × per_page ≥ total`:

```bash
page=1
while :; do
  body=$(curl -s "https://management.example.com/api/v1/users?per_page=100&page=$page" \
    -H "Authorization: Bearer $TOKEN")
  echo "$body" | jq -c '.items[]'
  [ $(( page * 100 )) -ge $(echo "$body" | jq .total) ] && break
  page=$(( page + 1 ))
done
```

Pages are counted from the newest item, so an item created while you read shifts the rest by one,
and you may see an item twice. Deduplicate by `id` when that matters. To copy a whole connection's
accounts, an export (`POST /api/v1/jobs/users-exports`) is the better tool.

A collection that is small by nature, such as a user's roles (`GET /api/v1/users/{user_id}/roles`) or
passkeys, is a plain JSON array with no paging.

## Search

The lists of users, clients, APIs, roles, initial access tokens and provisioning tokens take `q`:

```bash
curl -s 'https://management.example.com/api/v1/users?q=@example.com' \
  -H "Authorization: Bearer $TOKEN"
```

`q` matches a **case-insensitive substring**, taken literally: `%` and `_` are ordinary characters,
not wildcards. It is at most 200 characters. It looks at:

| List | Fields searched |
|---|---|
| `GET /api/v1/users` | `email` |
| `GET /api/v1/clients` | `client_id`, `name` |
| `GET /api/v1/resource-servers` | `identifier`, `name` |
| `GET /api/v1/roles` | `name`, `description` |
| `GET /api/v1/initial-access-tokens` | `description` |
| `GET /api/v1/provisioning-tokens` | `description` |

`total` counts the matches, and paging works on them as on any list.

## Filters

A few lists take filters of their own, listed with each operation in the reference:

- **The audit trail** (`GET /api/v1/audit-events`) filters on `type`, `outcome`, `actor_user_id`,
  `client_id`, `target_type` and `target_id`, between `since` and `until`.
- **Provisioning tokens** filter on their `connection`.

Filters combine: an event must match all of them to be listed.

## Parameters are exact

Every parameter is read exactly as the reference describes it:
- one the operation doesn't take is refused (`422`, `"Is not a parameter of this operation."`);
- a parameter sent twice is refused (`400`);
- a number is digits only: `per_page=02` is `"Must be an integer."`.

So a misspelt `per-page` fails at once, instead of silently giving 50 items.
