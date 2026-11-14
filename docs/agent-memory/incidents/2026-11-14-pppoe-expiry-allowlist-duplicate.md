# 2026-11-14 PPPoE expiry redirect apply failed on a duplicate address

## Summary

Enabling the expired PPPoE payment page on router 576 timed out, then failed after starting RouterOS configuration.

## Symptoms

The application logged `/ip/firewall/address-list/add: failure: already have such entry`. RouterOS had created the pool, PPP profile, and proxy redirect. The database flag remained off and the payment-page data endpoint returned 404.

## Cause

RouterOS had already put the literal IP in the allowlist as a dynamic DNS result of a hostname in the same list. Adding the static IP duplicate failed. The standard apply enables the proxy before it writes the filter rules, so this error also left the new proxy without its intended input guard.

## Fix

The scoped live recovery first installed the missing proxy guard. It then completed the standard enablement on router 576 while accepting the DNS-backed duplicate after verifying the exact enabled entry and its parent hostname. The app change applies the same validation when RouterOS rejects a redundant literal address.

## Verification

The router's saved configuration is enabled. Live readback verified the pool, profile, allowed hosts, proxy redirect, filter and NAT order, and the payment-page endpoint returned 200. Focused redirect and flow tests passed. The customer was asked to test from a naturally expired PPPoE line.

## Follow-Up Work

Publish the app fix after repository and branch authorization. Investigate the scheduling delay on the shared router-operation lock and ensure a newly enabled proxy gets its guard before the rest of the apply.
