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
main = sha256_test

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
sha256_test = putStrLn $ sha256PBKDF2 "password" "salt" 10000 32


-- SHA-based pbkdf2 generators

sha1PBKDF2 :: String -> String -> Int -> Int -> String
sha1PBKDF2 =
    pbkdf2
        PRF
            { prf_hash      = hmac sha1 64          -- 512-bit block
            , prf_hLen      = 20                    -- 160-bit hash
            } 
  where
    sha1 = toBytes . (CH.hash :: BS.ByteString -> CH.Digest CH.SHA1)

sha256PBKDF2 :: String -> String -> Int -> Int -> String
sha256PBKDF2 =
    pbkdf2
        PRF
            { prf_hash      = hmac sha256 64        -- 512-bit block
            , prf_hLen      = 32                    -- 256-bit hash
            } 
  where
    sha256 = toBytes . (CH.hash :: BS.ByteString -> CH.Digest CH.SHA256)

sha512PBKDF2 :: String -> String -> Int -> Int -> String
sha512PBKDF2 =
    pbkdf2
        PRF
            { prf_hash      = hmac sha512 128       -- 1024-bit block
            , prf_hLen      = 64                    --  512-bit hash
            } 
  where
    sha512 = toBytes . (CH.hash :: BS.ByteString -> CH.Digest CH.SHA512)

-- pbkdf2: parametrized over the psuedo-random/HMAC function

pbkdf2 :: PRF -> String -> String -> Int -> Int -> String
pbkdf2 prf pw_s na_s c dkLen =
    pbkdf2_
        PBKDF2
            { pbkdf2_PRF    = prf
            , pbkdf2_P      = BC.pack pw_s
            , pbkdf2_S      = BC.pack na_s
            , pbkdf2_c      = c
            , pbkdf2_dkLen  = dkLen
            }

data PBKDF2
    = PBKDF2
        { pbkdf2_PRF    :: PRF              -- the psuedo-random (i.e., HMAC) function
        , pbkdf2_P      :: BS.ByteString    -- the password (will be UTF-8 encoded)
        , pbkdf2_S      :: BS.ByteString    -- the salt     (will be UTF-8 encoded)
        , pbkdf2_c      :: Int              -- iteration count for applying the HMAC
        , pbkdf2_dkLen  :: Int              -- the length of the o/p derived key 
        }

data PRF
    = PRF
        { prf_hash      :: BS.ByteString -> BS.ByteString -> BS.ByteString  -- the HMAC function
        , prf_hLen      :: Int                                              -- number of octets in o/p hash
        } 


-- pbkdf2_: core PBKDF2 function

pbkdf2_ :: PBKDF2 -> String
pbkdf2_ PBKDF2{..} =
    dumpRaw $ take pbkdf2_dkLen $ BS.unpack $ BS.concat $ map f $ zip zbs ivs
  where
    f (zb,iv)   = snd $ b_i zb $ pbkdf2_S `BS.append` iv

    b_i zb msg  = iterateK pbkdf2_c g (msg,zb)

    g (!u,!p)   = (u',BS.pack $ BS.zipWith xor p u')
      where
        u' = prf_hash pbkdf2_P u

    r           = pbkdf2_dkLen - (l - 1) * prf_hLen

    l           = ceiling $ (fromIntegral pbkdf2_dkLen :: Double) / fromIntegral prf_hLen
    
    zbs         = replicate l (mk_zb prf_hLen) ++ [mk_zb r]
    
    mk_zb sz    = BS.pack $ replicate sz 0

    PRF{..}     = pbkdf2_PRF

ivs :: [BS.ByteString]
ivs = [ BS.pack $ drop (length a - 4) a | i<-bnos, let a = BLC.unpack $ B.encode i ]
  where
    bnos = [1..] :: [Int]

iterateK :: Int -> (a->a) -> a -> a
iterateK !i f !x =
    case i of
      0 -> x
      _ -> iterateK (i-1) f $ f x


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
