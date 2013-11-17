{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE RecordWildCards    #-}

module Crypto.PBKDF.ByteString
    ( 
   
    --     
    -- * Password Based Key Derivation Functions
    --
    -- $summary

    --    
    -- * SHA-based PBKDF1 functions
    --

      sha1PBKDF1
    , sha256PBKDF1
    , sha512PBKDF1

    --
    -- * SHA-based PBKDF2 functions
    --

    , sha1PBKDF2
    , sha256PBKDF2
    , sha512PBKDF2
    ) where

import           Crypto.PBKDF.Core
import qualified Data.ByteString            as BS


-- $summary
--
-- This module provides stock implementations of the PBKDF functions from
-- RFC-2898 (<http://www.ietf.org/rfc/rfc2898.txt>), based on the SHA-1,
-- SHA-256 and SHA-256 hash functions. Each function takes the password and
-- salt as a ByteString and returns the Hash as a ByteString.


sha1PBKDF1, sha256PBKDF1, sha512PBKDF1 
    :: BS.ByteString    -- ^ the password 
    -> BS.ByteString    -- ^ the salt
    -> Int              -- ^ the iteration count
    -> BS.ByteString    -- ^ the result key
sha1PBKDF1   pw_s na_s c = pbkdf1 $ sha1PBKDF'   pw_s na_s c 0
sha256PBKDF1 pw_s na_s c = pbkdf1 $ sha256PBKDF' pw_s na_s c 0
sha512PBKDF1 pw_s na_s c = pbkdf1 $ sha512PBKDF' pw_s na_s c 0


sha1PBKDF2, sha256PBKDF2, sha512PBKDF2
    :: BS.ByteString    -- ^ the password 
    -> BS.ByteString    -- ^ the salt
    -> Int              -- ^ the iteration count
    -> Int              -- ^ the length of the key to be generated (in octets)
    -> BS.ByteString    -- ^ the result key

sha1PBKDF2   pw_s na_s c dkLen = pbkdf2 $ sha1PBKDF'   pw_s na_s c dkLen
sha256PBKDF2 pw_s na_s c dkLen = pbkdf2 $ sha256PBKDF' pw_s na_s c dkLen
sha512PBKDF2 pw_s na_s c dkLen = pbkdf2 $ sha512PBKDF' pw_s na_s c dkLen
