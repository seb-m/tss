# Threshold Secret Sharing

Implementation of Shamir's secret sharing scheme [http://tools.ietf.org/html/draft-mcgrew-tss-03](http://tools.ietf.org/html/draft-mcgrew-tss-03)

## Example

    import tss
    # Create 8 shares of the secret recoverable from at least 5
    # differents shares. Use secretid42 as identifier and hash the
    # secret with sha256.
    shares = tss.share_secret(5, 8, 'my shared secret', 'secretid42',
                              tss.Hash.SHA256)
    try:
        # Recover the secret value
        secret = tss.reconstruct_secret(shares)
    except tss.TSSError:
        pass  # Handling error

## Notes

* Operations are _not_ constant-time, and are quite verbose too
* This implementation doesn't provide ECC encoding/decoding
