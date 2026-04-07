# Safaricom M-Pesa Certificates

Place Safaricom's public certificates here for B2B SecurityCredential generation.

## How to get the certificates

1. Go to https://developer.safaricom.co.ke/APIs/GettingStarted
2. Download the certificates from the documentation page
3. Place them in this folder as:
   - `SandboxCertificate.cer` (for sandbox/testing)
   - `ProductionCertificate.cer` (for production)

## Alternative: Use pre-encrypted SecurityCredential

If you don't want to place certificates here, you can:

1. Go to https://developer.safaricom.co.ke/APIs/GettingStarted
2. Use the "Generate Security Credential" tool on that page
3. Paste the result into `MPESA_B2B_SECURITY_CREDENTIAL` in your `.env`
4. Leave `MPESA_B2B_INITIATOR_PASSWORD` empty

The system will use the pre-encrypted credential directly and skip certificate-based encryption.
