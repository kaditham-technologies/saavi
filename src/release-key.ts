// The Saavi release signing key — the PUBLIC half, pinned in the app so a
// .deb self-update can verify the GPG-signed checksum list offline against
// the same trust root the download page documents. Fingerprint and armor
// must match what release.yml publishes as saavi_pubkey.gpg.
export const RELEASE_KEY_FPR = 'DCF5773B84E9AABA785FD5A84D2AECE68A953F46';

export const RELEASE_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaoROVBYJKwYBBAHaRw8BAQdAs3pu7h8V7taAVLUuf88L2a9zHK9woUECkqTt
qG+S1O60LVNhYXZpIHJlbGVhc2Ugc2lnbmluZyA8d2VibWFzdGVyQGthZGl0aGFt
Lm1lPoiWBBMWCgA+FiEE3PV3O4Tpqrp4X9WoTSrs5oqVP0YFAmqETlQCGwMFCQPC
ZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQTSrs5oqVP0YKzgEAvWBrTsus
ZU48QpJlRLqfL+NoGF4fOyTcuXVodmAEQbYA/izffkhmzw8lPmjzvijoFv0YuYO6
OX3Ehr2VCtIWhB4B
=AnGc
-----END PGP PUBLIC KEY BLOCK-----
`;
