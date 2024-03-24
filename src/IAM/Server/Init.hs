{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Init (initDB) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding
import Data.UUID.V4

import IAM.IAM
import IAM.Server.IAM.DB


initDB :: DB db => Text -> Text -> db -> IO db
initDB adminEmail adminPublicKeyBase64 db = do
  createAdmin adminEmail adminPublicKeyBase64 db
  return db


createAdmin :: DB db => Text -> Text -> db -> IO ()
createAdmin adminEmail adminPublicKeyBase64 db = do
  adminPolicyId <- nextRandom

  -- Create the admin policy
  let allowReads = Rule Allow Read "*"
      allowWrites = Rule Allow Write "*"
      adminPolicy = Policy adminPolicyId [allowReads, allowWrites]
  r0 <- runExceptT $ createPolicy db adminPolicy
  case r0 of
    Left AlreadyExists -> return ()
    Left e -> error $ "Error creating admin policy: " ++ show e
    Right _ -> return ()

  -- Create the admins group
  let adminsGroupId = GroupName "admins"
      adminsGroup = Group adminsGroupId [] [adminPolicyId]
  r1 <- runExceptT $ createGroup db adminsGroup
  case r1 of
    Left AlreadyExists -> return ()
    Left e -> error $ "Error creating admins group: " ++ show e
    Right _ -> return ()

  -- Create the admin user
  case decodeBase64 $ encodeUtf8 adminPublicKeyBase64 of
    Left _ -> error "Invalid base64 public key"
    Right adminPublicKey -> do
      let pk = PublicKey adminPublicKey
      let user = User (UserEmail adminEmail) [adminsGroupId] [] [pk]
      r2 <- runExceptT $ createUser db user
      case r2 of
        Left AlreadyExists -> return ()
        Left e -> error $ "Error creating admin: " ++ show e
        Right _ -> return ()
