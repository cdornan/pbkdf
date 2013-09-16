{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE RecordWildCards    #-}

module Crypto.PBKDF.Core
    ( sha1PBKDF
    , sha256PBKDF
    , sha512PBKDF
    , pbkdf
    , PBKDF(..)
    , PRF(..)
    , pbkdf1_
    , pbkdf2_
    ) where

import qualified Data.Binary                    as B
import           Data.Bits
import qualified Data.ByteString                as BS
import qualified Data.ByteString.UTF8           as BU
import qualified Data.ByteString.Lazy           as BLC
import qualified Crypto.Hash                    as CH
import           Crypto.MAC.HMAC
import           Data.Byteable


-- | SHA-1 generator

sha1PBKDF :: String -> String -> Int -> Int -> PBKDF
sha1PBKDF =
    pbkdf
        PRF
            { prf_hmac      = hmac sha1 64          -- 512-bit block
            , prf_hash      = sha1                  -- SHA-1
            , prf_hLen      = 20                    -- 160-bit hash
            } 
  where
    sha1 = toBytes . (CH.hash :: BS.ByteString -> CH.Digest CH.SHA1)

-- | SHA-256 generator

sha256PBKDF :: String -> String -> Int -> Int -> PBKDF
sha256PBKDF =
    pbkdf
        PRF
            { prf_hmac      = hmac sha256 64        -- 512-bit block
            , prf_hash      = sha256                -- SHA-256
            , prf_hLen      = 32                    -- 256-bit hash
            } 
  where
    sha256 = toBytes . (CH.hash :: BS.ByteString -> CH.Digest CH.SHA256)

-- | SHA-512 generator

sha512PBKDF :: String -> String -> Int -> Int -> PBKDF
sha512PBKDF =
    pbkdf
        PRF
            { prf_hmac      = hmac sha512 128       -- 1024-bit block
            , prf_hash      = sha512                -- SHA-512
            , prf_hLen      = 64                    -- 512-bit hash
            } 
  where
    sha512 = toBytes . (CH.hash :: BS.ByteString -> CH.Digest CH.SHA512)

-- | construct a PBKDF generator from a HMAC function

pbkdf :: PRF -> String -> String -> Int -> Int -> PBKDF
pbkdf prf pw_s na_s c dkLen =
    PBKDF
        { pbkdf_PRF    = prf
        , pbkdf_P      = BU.fromString pw_s
        , pbkdf_S      = BU.fromString na_s
        , pbkdf_c      = c
        , pbkdf_dkLen  = dkLen
        }

-- | PBKDF generator parameters

data PBKDF
    = PBKDF
        { pbkdf_PRF    :: PRF              -- ^ the psuedo-random (i.e., HMAC) function
        , pbkdf_P      :: BS.ByteString    -- ^ the password (will be UTF-8 encoded)
        , pbkdf_S      :: BS.ByteString    -- ^ the salt     (will be UTF-8 encoded)
        , pbkdf_c      :: Int              -- ^ iteration count for applying the HMAC
        , pbkdf_dkLen  :: Int              -- ^ the length of the o/p derived key 
        }

-- | the HMAC function and its underlying HASH function

data PRF
    = PRF
        { prf_hmac      :: BS.ByteString -> BS.ByteString -> BS.ByteString  -- ^ the PR/HMAC function
        , prf_hash      :: BS.ByteString -> BS.ByteString                   -- ^ the underlying hash function
        , prf_hLen      :: Int                                              -- ^ number of octets in o/p hash
        } 


-- | the pbkdf1_ core function

pbkdf1_ :: PBKDF -> BS.ByteString
pbkdf1_ PBKDF{..} = iterate_n pbkdf_c prf_hash $ pbkdf_P `BS.append` pbkdf_S
  where
    PRF{..} = pbkdf_PRF

-- | the pbkdf2_ core function

pbkdf2_ :: PBKDF -> BS.ByteString
pbkdf2_ PBKDF{..} = BS.take pbkdf_dkLen $ BS.concat $ map f $ zip zbs ivs
  where
    f (zb,iv)   = snd $ itr zb $ pbkdf_S `BS.append` iv

    itr zb msg  = iterate_n pbkdf_c g (msg,zb)

    g (!u,!p)   = (u',BS.pack $ BS.zipWith xor p u')
      where
        u' = prf_hmac pbkdf_P u

    r           = pbkdf_dkLen - (l - 1) * prf_hLen

    l           = ceiling $ (fromIntegral pbkdf_dkLen :: Double) / fromIntegral prf_hLen
    
    zbs         = replicate l (mk_zb prf_hLen) ++ [mk_zb r]
    
    mk_zb sz    = BS.pack $ replicate sz 0

    PRF{..}     = pbkdf_PRF

    ivs         = [ BS.pack $ drop (length os - 4) os | bno<-[1..] :: [Int], 
                                            let os = BLC.unpack $ B.encode bno ]

-- iterate a function over an argument k times

iterate_n :: Int -> (a->a) -> a -> a
iterate_n !i f !x =
    case i of
      0 -> x
      _ -> iterate_n (i-1) f $ f x
