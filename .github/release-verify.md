Verifying Saavi {TAG}

1. Download the asset you want, its detached signature (.sig), and
   saavi_pubkey.gpg from this release.

2. Import the key:

       gpg --import saavi_pubkey.gpg

3. Check the fingerprint:

       gpg --fingerprint "Saavi release signing"

   It must read, exactly:

       DCF5 773B 84E9 AABA 785F  D5A8 4D2A ECE6 8A95 3F46

   Compare it against https://kaditham.ie/saavi/ — published outside
   GitHub, so a compromised repository cannot swap the key and the
   binaries together. If it differs, stop and write to
   security@kaditham.me (see SECURITY.md in the repository).

4. Verify the asset:

       gpg --verify <asset>.sig <asset>

   Expect: Good signature from "Saavi release signing
   <webmaster@kaditham.me>". A "key is not certified" warning is
   normal here; step 3 is what establishes the trust.

This message is clearsigned by the same release key: save it to a
file and run gpg --verify on it to check it has not been altered.
