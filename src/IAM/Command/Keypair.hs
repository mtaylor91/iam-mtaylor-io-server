{-# LANGUAGE OverloadedStrings #-}
module IAM.Command.Keypair
  ( keypair
  , keypairOptions
  , KeypairOptions(..)
  ) where

import Crypto.Sign.Ed25519
import Data.Aeson
import Data.ByteString.Base64
import Data.ByteString.Lazy (toStrict)
import Data.Text.Encoding
import Options.Applicative
import qualified Data.Text as T

import IAM.Config


data KeypairOptions = KeypairOptions
  { keypairEmail :: !T.Text
  , keypairShell :: !Bool
  } deriving (Show)


data UserKeypair = UserKeypair
  { userKeypairEmail :: !T.Text
  , userKeypairPublicKey :: !PublicKey
  , userKeypairSecretKey :: !SecretKey
  } deriving (Eq, Show)


instance FromJSON UserKeypair where
  parseJSON (Object obj) = do
    email <- obj .: "email"
    pkBase64 <- obj .: "publicKey"
    skBase64 <- obj .: "secretKey"
    case (decodeBase64 $ encodeUtf8 pkBase64, decodeBase64 $ encodeUtf8 skBase64) of
      (Right pk, Right sk) -> return $ UserKeypair email (PublicKey pk) (SecretKey sk)
      (_, _) -> fail "Invalid base64 encoding"
  parseJSON _ = fail "Invalid JSON object"


instance ToJSON UserKeypair where
  toJSON (UserKeypair email pk sk) = object
    [ "email" .= email
    , "publicKey" .= encodeBase64 (unPublicKey pk)
    , "secretKey" .= encodeBase64 (unSecretKey sk)
    ]


keypair :: KeypairOptions -> IO ()
keypair (KeypairOptions email formatShell) = do
  (pk, sk) <- createKeypair
  let keypair' = UserKeypair email pk sk
  if formatShell
    then printUserEmailShellVars email pk sk
    else putStrLn $ T.unpack $ decodeUtf8 $ toStrict $ encode $ toJSON keypair'
  return ()


keypairOptions :: Parser KeypairOptions
keypairOptions = KeypairOptions
  <$> argument str
      ( metavar "EMAIL"
     <> help "Email for keypair"
      )
  <*> switch
      ( long "shell"
     <> short 's'
     <> help "Format output for shell"
      )
