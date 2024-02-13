{-# LANGUAGE OverloadedStrings #-}
module Lib.Init (initDB) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding
import Data.UUID.V4

import Lib.IAM
import Lib.IAM.DB


initDB :: DB db => Text -> Text -> db -> IO db
initDB adminEmail adminPublicKeyBase64 db = do
  createAdmin adminEmail adminPublicKeyBase64 db
  return db


createAdmin :: DB db => Text -> Text -> db -> IO ()
createAdmin adminEmail adminPublicKeyBase64 db = do
  case decodeBase64 $ encodeUtf8 adminPublicKeyBase64 of
    Left _ -> error "Invalid base64 public key"
    Right adminPublicKey -> do
      let pk = PublicKey adminPublicKey
      r0 <- runExceptT $ createUser db $ UserPrincipal (UserEmail adminEmail) pk
      case r0 of
        Left AlreadyExists -> return ()
        Left e -> error $ "Error creating admin: " ++ show e
        Right (UserPrincipal adminUserId _) -> do
          adminPolicyId <- nextRandom
          let adminPolicy = Policy adminPolicyId [allowReads, allowWrites]
              allowReads = Rule Allow Read "*"
              allowWrites = Rule Allow Write "*"
          r1 <- runExceptT $ createPolicy db adminPolicy
          case r1 of
            Left AlreadyExists -> return ()
            Left e -> error $ "Error creating admin policy: " ++ show e
            Right _ -> do
              r2 <- runExceptT $ createUserPolicyAttachment db adminUserId adminPolicyId
              case r2 of
                Left AlreadyExists -> return ()
                Left e -> error $ "Error attaching admin policy: " ++ show e
                Right _ ->
                  return ()
