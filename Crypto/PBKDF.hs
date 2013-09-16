{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE RecordWildCards    #-}

module Crypto.PBKDF 
    ( sha1PBKDF1
    , sha256PBKDF1
    , sha512PBKDF1
    , sha1PBKDF2
    , sha256PBKDF2
    , sha512PBKDF2
    ) where

import           Crypto.PBKDF.Core
import           Text.Bytedump


-- | Password Based Key Derivation Functions:
--   This module provides stock implementations of the PBKDF functions from
--   RFC-2898 based on the SHA-1, SHA-256 and SHA-256 hash functions. Each
--   function takes the password and salt as a string and returns a hex
--   string. To work with ByteStrings and provide your own hash and
--   psuedo-random use the Crypto.PBKDF.Core that are used to implement
--   these functions.


-- | SHA-based PBKDF1 functions

sha1PBKDF1, sha256PBKDF1, sha512PBKDF1 
    :: String   -- ^ the password (will be encoded with UTF-8) 
    -> String   -- ^ the salt     (will be encoded with UTF-8)
    -> Int      -- ^ the iteration count
    -> String   -- ^ the result key as a hex string
sha1PBKDF1   pw_s na_s c = dumpRawBS $ pbkdf1_ $ sha1PBKDF   pw_s na_s c 0
sha256PBKDF1 pw_s na_s c = dumpRawBS $ pbkdf1_ $ sha256PBKDF pw_s na_s c 0
sha512PBKDF1 pw_s na_s c = dumpRawBS $ pbkdf1_ $ sha512PBKDF pw_s na_s c 0


-- | SHA-based PBKDF2 functions

sha1PBKDF2, sha256PBKDF2, sha512PBKDF2
    :: String   -- ^ the password (will be encoded with UTF-8) 
    -> String   -- ^ the salt     (will be encoded with UTF-8)
    -> Int      -- ^ the iteration count
    -> Int      -- ^ the length of the key to be generated (in octets)
    -> String   -- ^ the result key as a hex string

sha1PBKDF2   pw_s na_s c dkLen = dumpRawBS $ pbkdf2_ $ sha1PBKDF   pw_s na_s c dkLen
sha256PBKDF2 pw_s na_s c dkLen = dumpRawBS $ pbkdf2_ $ sha256PBKDF pw_s na_s c dkLen
sha512PBKDF2 pw_s na_s c dkLen = dumpRawBS $ pbkdf2_ $ sha512PBKDF pw_s na_s c dkLen
