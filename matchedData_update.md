# Adding matchedData to an Existing WAF

When AWS WAF evaluates a request against a rule that uses regex matching, it can include `matchedData` in the CloudWatch Log record. This surfaces the actual content that triggered the rule -- auth tokens in the body, Authorization header values, query string credentials -- directly in the WAF log JSON. ***waf-fu*** uses this to flag entries with a `⚑` marker in the TUI.

By default, WAF logs only capture headers, URI, and the query args. `matchedData` adds a second signal: the specific substrings that matched your detection patterns, with their field location. This is especially useful for body-based auth (POST login forms, OAuth token requests, API keys in JSON payloads) where you want to confirm the auth content was captured before attempting replay.

## What You Need

- An existing WAFv2 Web ACL (REGIONAL or CLOUDFRONT scope)
- CloudWatch Logs logging already enabled for that ACL
- Permissions: `wafv2:UpdateWebACL`, `wafv2:CreateRegexPatternSet`, `wafv2:GetWebACL`

## How matchedData Works

When a WAF rule uses a `RegexPatternSetReferenceStatement` and matches, the log entry's `ruleGroupList` includes:

```json
{
  "nonTerminatingMatchingRules": [
    {
      "ruleId": "detect-body-auth",
      "action": "COUNT",
      "ruleMatchDetails": [
        {
          "conditionType": "REGEX",
          "location": "BODY",
          "matchedData": ["eyJhbGciOiJSUzI1NiIsInR5cCI6..."]
        }
      ]
    }
  ]
}
```

Key points:
- Only `RegexPatternSetReferenceStatement` produces `matchedData`. Size constraints, IP sets, geo matching, label matching, and string match statements do NOT.
- The rule action must be `COUNT` (not `BLOCK` or `ALLOW`) for non-terminating match details to appear in `ruleGroupList`. Terminating rules end evaluation and only populate `terminatingRuleId`.
- `matchedData` contains the actual matched substring, not the full field value.

## Step-by-Step

### Create Pattern Sets

```bash
aws wafv2 create-regex-pattern-set \
  --name body-auth-detect \
  --scope REGIONAL \
  --regular-expression-list \
    '[{"RegexString":"eyJ[A-Za-z0-9_-]{10,}"},
      {"RegexString":"AKIA[A-Z0-9]{16}"},
      {"RegexString":"aws4_request"},
      {"RegexString":"client.credentials"}]'
```

Save the returned ARN. Repeat for `header-auth-detect` and `query-auth-detect` with their respective patterns.

### Update the Web ACL

Fetch your current ACL config (you need the `LockToken`):

```bash
aws wafv2 get-web-acl \
  --name YOUR_ACL_NAME \
  --scope REGIONAL \
  --id YOUR_ACL_ID
```

Add the new rules to the existing `Rules` array in the JSON. Each rule looks like:

```json
{
  "Name": "detect-body-auth",
  "Priority": 0,
  "Action": { "Count": {} },
  "Statement": {
    "RegexPatternSetReferenceStatement": {
      "ARN": "arn:aws:wafv2:REGION:ACCOUNT:regional/regexpatternset/body-auth-detect/ID",
      "FieldToMatch": {
        "Body": { "OversizeHandling": "CONTINUE" }
      },
      "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "detect-body-auth"
  }
}
```

Then update:

```bash
aws wafv2 update-web-acl \
  --name YOUR_ACL_NAME \
  --scope REGIONAL \
  --id YOUR_ACL_ID \
  --lock-token LOCK_TOKEN \
  --default-action '{"Allow":{}}' \
  --rules file://updated-rules.json \
  --visibility-config '{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"YOUR_ACL_NAME"}'
```

## Limitations and Gotchas

**Body size limit**: WAF inspects only the first 8 KB of the request body by default. With `oversize_handling = "CONTINUE"`, WAF processes what it can and lets the request through, but `matchedData` only reflects content within the inspected portion. If auth tokens appear beyond 8 KB in the body, they won't be matched.

**Regex pattern set limits**: Each pattern set can hold up to 10 regex patterns. Each regex has a 200-character limit. If you need more patterns, create additional pattern sets and rules.

**Rule count limits**: Web ACLs have a capacity limit (WCU). Each regex pattern set rule consumes WCUs based on the number of patterns and the field inspected. Body inspection costs more WCUs than header inspection. Check your remaining capacity before adding rules.

**COUNT vs BLOCK ordering**: COUNT rules must fire before any BLOCK rule that would terminate evaluation. If a managed rule group (like AWS Managed Rules) blocks a request at priority 5, your COUNT rule at priority 10 never executes. Always place detection rules at the lowest priority numbers.

**matchedData is the matched substring**: It's not the full field value. A body containing `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig","user":"admin"}` would produce matchedData of `["eyJhbGciOiJIUzI1NiJ9"]` (just the matched portion). The full body is NOT available in WAF logs -- WAFv2 never logs body content, only body size metadata (`requestBodySize`). To capture full body content, use application-level logging or API Gateway access logs.

**WAF logs do not contain the POST body**: WAFv2 logs never include the actual request body content. The `httpRequest` object contains headers, URI, query string, and method, but no body field. WAF logs do include `requestBodySize` and `requestBodySizeInspectedByWAF` (integers showing byte counts, not content). The only body-derived data that appears in logs is `matchedData` itself -- the specific substrings that triggered regex rules. For body-based auth detection, `matchedData` is your signal that auth content was present. If you need the full POST body for replay, you must capture it outside WAF: application-level logging, API Gateway custom access logs (`$request.body`), or Lambda@Edge with `includeBody` on the ViewerRequest trigger.

**CloudFront scope**: If your WAF is attached to a CloudFront distribution, use `scope = "CLOUDFRONT"` and deploy to `us-east-1` (CloudFront WAFs must be in us-east-1).

## Verifying It Works

After adding the rules, send a test request with auth content:

```bash
curl -X POST https://your-api.example.com/test \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.fakesig"}'
```

Then check the CloudWatch Log entry. In ***waf-fu***, entries with matchedData display a `⚑` marker in the TUI list view, and the detail pane shows a MATCHED DATA section with the rule name, field location, and matched content.
