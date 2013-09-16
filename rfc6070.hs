
import           Crypto.PBKDF
import           Text.Printf
import           Control.Applicative
import           System.Exit


main :: IO ()
main = 
 do ok <- run_tests
    case ok of
      True  -> return ()
      False -> exitWith $ ExitFailure 1

run_tests :: IO Bool
run_tests = and <$> mapM test test_vectors
  where
    test (pw,na,c,out) =
     do putStr $ printf "%-30s %-40s %8d (%d) : " (show pw) (show na) c dkl
        case ok of
          True  -> putStrLn          "passed"
          False -> putStrLn $ printf "FAILED (%s[%d])" t_out (length t_out)
        return ok
      where
        ok    = t_out == out
        t_out = sha1PBKDF2 pw na c dkl
        dkl   = length out `div` 2

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

--simple_test :: IO ()
--simple_test = putStrLn $ sha1PBKDF2   "password" "salt" 4096  20

--sha256_test :: IO ()
--sha256_test = putStrLn $ sha256PBKDF2 "password" "salt" 1000000 32

