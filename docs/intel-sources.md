# Alert2Case — Threat Intelligence Sources

## 1. Purpose

This document describes the Threat Intelligence APIs used by the Alert2Case project.

The project uses three external services:
- VirusTotal
- AbuseIPDB
- AlienVault OTX

API keys must never be stored in this document or committed to GitHub.

## 2. VirusTotal

- API Version: v3
- Base URL: https://www.virustotal.com/api/v3
- Authentication Header: x-apikey
- Environment Variable: VT_API_KEY

### Supported Observables
- IP address: /ip_addresses/{ip}
- Domain: /domains/{domain}
- File hash: /files/{hash}
- URL: /urls/{id}

### Main Scoring Fields
- last_analysis_stats
- malicious
- suspicious

### API Limits
- Public API limits must be checked against the active account plan.
- HTTP 429 indicates rate limiting.

### HTTP Responses
- 200: Successful request
- 401/403: Authentication or access problem
- 404: Observable not found
- 429: Rate limit exceeded
- 5xx: Server-side error

### Test Evidence
- Observable: google.com
- HTTP Status: 200
- Test Date: 2026-10-26

## 3. AbuseIPDB

- API Version: v2
- Base URL: https://api.abuseipdb.com/api/v2
- Endpoint: /check
- Authentication Header: Key
- Environment Variable: ABUSEIPDB_API_KEY

### Supported Observables
- IP address

### Request Parameters
- ipAddress
- maxAgeInDays=90

### Main Scoring Fields
- abuseConfidenceScore
- totalReports
- isWhitelisted
- isTor

### API Limits
- Limits depend on the active account plan.
- HTTP 429 indicates rate limiting.

### HTTP Responses
- 200: Successful request
- 401/403: Authentication or access problem
- 429: Rate limit exceeded
- 5xx: Server-side error

### Test Evidence
- Observable: 8.8.8.8
- HTTP Status: 200
- Test Date: 2026-10-26

## 4. AlienVault OTX

- Base URL: https://otx.alienvault.com/api/v1
- Endpoint: /indicators/IPv4/{ip}/general
- Authentication Header: X-OTX-API-KEY
- Environment Variable: OTX_API_KEY

### Supported Observables
- IPv4 address (tested endpoint)

### Main Scoring Field
- pulse_info.count

### API Limits
- Account-specific limits must be verified.
- HTTP 429 indicates rate limiting.

### HTTP Responses
- 200: Successful request
- 401/403: Authentication or access problem
- 404: Indicator or endpoint not found
- 429: Rate limit exceeded
- 5xx: Server-side error

### Test Evidence
- Observable: 8.8.8.8
- HTTP Status: 200
- Test Date: 2026-10-26

## 5. Current Verification Status

| Service | Authentication Test | Result |
|---|---|---|
| VirusTotal | GET /domains/google.com | HTTP 200 |
| AbuseIPDB | GET /check?ipAddress=8.8.8.8 | HTTP 200 |
| AlienVault OTX | GET /indicators/IPv4/8.8.8.8/general | HTTP 200 |

## 6. Remaining Work

- Collect and sanitize at least 8 JSON fixtures.
- Include a VirusTotal HTTP 404 fixture.
- Verify API limits against provider documentation.
- Move this document into the project's docs/ directory when the shared repository is available.
- Create a pull request for review.

## 7. Security Rules

- Never commit API keys.
- Never share API keys in screenshots.
- Store secrets in a gitignored .env file when the repository is ready.
- Remove sensitive information from fixtures before committing.