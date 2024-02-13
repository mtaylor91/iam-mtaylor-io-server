{-# LANGUAGE OverloadedStrings #-}
module Lib.Keypair (generateKeypair) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64 (encodeBase64)
import qualified Data.Text as T


generateKeypair :: IO ()
generateKeypair = do
  (pk, sk) <- createKeypair
  putStrLn $ "Public key: " ++ T.unpack (encodeBase64 $ unPublicKey pk)
  putStrLn $ "Secret key: " ++ T.unpack (encodeBase64 $ unSecretKey sk)
  return ()
