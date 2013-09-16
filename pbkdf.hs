{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE RecordWildCards    #-}

import qualified Data.Binary                    as B
import           Data.Bits
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as BC
import qualified Data.ByteString.Lazy           as BLC
import qualified Crypto.Hash                    as CH
import           Crypto.MAC.HMAC
import           Text.Bytedump
import           Data.Byteable
import           Text.Printf


main :: IO ()
main = run_tests

run_tests :: IO ()
run_tests = mapM_ test test_vectors
  where
    test (pw,na,c,out) =
     do putStr $ printf "%-30s %-40s %8d (%d) : " (show pw) (show na) c dkl
        case t_out == out of
          True  -> putStrLn          "passed"
          False -> putStrLn $ printf "FAILED (%s[%d])" t_out (length t_out)
      where
        t_out = sha1PBKDF2 pw na c dkl
        dkl   = length out `div` 2

simple_test :: IO ()
simple_test = putStrLn $ sha1PBKDF2   "password" "salt" 4096  20

sha256_test :: IO ()
sha256_test = putStrLn $ sha256PBKDF2 "password" "salt" 1000000 32

sha1PBKDF1, sha256PBKDF1, sha512PBKDF1 :: String -> String -> Int -> String 
sha1PBKDF1   pw_s na_s c = pbkdf1_ $ sha1PBKDF   pw_s na_s c 0
sha256PBKDF1 pw_s na_s c = pbkdf1_ $ sha256PBKDF pw_s na_s c 0
sha512PBKDF1 pw_s na_s c = pbkdf1_ $ sha512PBKDF pw_s na_s c 0

sha1PBKDF2, sha256PBKDF2, sha512PBKDF2 :: String -> String -> Int -> Int -> String

sha1PBKDF2   pw_s na_s c dkLen = pbkdf2_ $ sha1PBKDF   pw_s na_s c dkLen
sha256PBKDF2 pw_s na_s c dkLen = pbkdf2_ $ sha256PBKDF pw_s na_s c dkLen
sha512PBKDF2 pw_s na_s c dkLen = pbkdf2_ $ sha512PBKDF pw_s na_s c dkLen

-- SHA-based pbkdf generators

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

pbkdf :: PRF -> String -> String -> Int -> Int -> PBKDF
pbkdf prf pw_s na_s c dkLen =
    PBKDF
        { pbkdf_PRF    = prf
        , pbkdf_P      = BC.pack pw_s
        , pbkdf_S      = BC.pack na_s
        , pbkdf_c      = c
        , pbkdf_dkLen  = dkLen
        }

-- PBKDF parameters

data PBKDF
    = PBKDF
        { pbkdf_PRF    :: PRF              -- the psuedo-random (i.e., HMAC) function
        , pbkdf_P      :: BS.ByteString    -- the password (will be UTF-8 encoded)
        , pbkdf_S      :: BS.ByteString    -- the salt     (will be UTF-8 encoded)
        , pbkdf_c      :: Int              -- iteration count for applying the HMAC
        , pbkdf_dkLen  :: Int              -- the length of the o/p derived key 
        }

data PRF
    = PRF
        { prf_hmac      :: BS.ByteString -> BS.ByteString -> BS.ByteString  -- the PR/HMAC function
        , prf_hash      :: BS.ByteString -> BS.ByteString                   -- the underlying hash function
        , prf_hLen      :: Int                                              -- number of octets in o/p hash
        } 

-- core PBKDF functions

pbkdf1_ :: PBKDF -> String
pbkdf1_ PBKDF{..} = dumpRaw $ BS.unpack $ iterate_n pbkdf_c prf_hash $ pbkdf_P `BS.append` pbkdf_S
  where
    PRF{..} = pbkdf_PRF

pbkdf2_ :: PBKDF -> String
pbkdf2_ PBKDF{..} =
    dumpRaw $ take pbkdf_dkLen $ BS.unpack $ BS.concat $ map f $ zip zbs ivs
  where
    f (zb,iv)   = snd $ b_i zb $ pbkdf_S `BS.append` iv

    b_i zb msg  = iterate_n pbkdf_c g (msg,zb)

    g (!u,!p)   = (u',BS.pack $ BS.zipWith xor p u')
      where
        u' = prf_hmac pbkdf_P u

    r           = pbkdf_dkLen - (l - 1) * prf_hLen

    l           = ceiling $ (fromIntegral pbkdf_dkLen :: Double) / fromIntegral prf_hLen
    
    zbs         = replicate l (mk_zb prf_hLen) ++ [mk_zb r]
    
    mk_zb sz    = BS.pack $ replicate sz 0

    PRF{..}     = pbkdf_PRF

-- ivs (helper) : PBKDF2 IVs

ivs :: [BS.ByteString]
ivs = [ BS.pack $ drop (length a - 4) a | i<-bnos, let a = BLC.unpack $ B.encode i ]
  where
    bnos = [1..] :: [Int]

-- iterate a function over an argument k times

iterate_n :: Int -> (a->a) -> a -> a
iterate_n !i f !x =
    case i of
      0 -> x
      _ -> iterate_n (i-1) f $ f x

-- RFC6070 test vectors

test_vectors :: [(String,String,Int,String)]
test_vectors = 
    [ (,,,) "password"                  "salt"                                  1           "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    , (,,,) "password"                  "salt"                                  2           "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
    , (,,,) "password"                  "salt"                                  4096        "4b007901b765489abead49d926f721d065a429c1"
    , (,,,) "password"                  "salt"                                  16777216    "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"
    , (,,,) "passwordPASSWORDpassword"  "saltSALTsaltSALTsaltSALTsaltSALTsalt"  4096        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
    , (,,,) "pass\0word"                "sa\0lt"                                4096        "56fa6aa75548099dcc37d7f03425e0c3"
    ]
