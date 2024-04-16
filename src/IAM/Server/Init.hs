{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Init (initDB) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding
import Data.UUID.V4

import IAM.Error
import IAM.Group
import IAM.GroupIdentifier
import IAM.Policy
import IAM.Server.DB
import IAM.User
import IAM.UserIdentifier


initDB :: DB db => Text -> Text -> Text -> db -> IO db
initDB host adminEmail adminPublicKeyBase64 db = do
  createAdmin host adminEmail adminPublicKeyBase64 db
  return db


createAdmin :: DB db => Text -> Text -> Text -> db -> IO ()
createAdmin host adminEmail adminPublicKeyBase64 db = do
  adminPolicyId <- PolicyUUID <$> nextRandom

  -- Create the admin policy
  let name = "iam-admin"
      allowReads = Rule Allow Read "*"
      allowWrites = Rule Allow Write "*"
      adminPolicy = Policy adminPolicyId (Just name) host [allowReads, allowWrites]
  r0 <- runExceptT $ createPolicy db adminPolicy
  case r0 of
    Left AlreadyExists -> return ()
    Left e -> error $ "Error creating admin policy: " ++ show e
    Right _ -> return ()

  -- Create the admins group
  adminsGroupId <- GroupUUID <$> nextRandom
  let adminsGroup = Group adminsGroupId (Just "admins") [] [PolicyId adminPolicyId]
  r1 <- runExceptT $ createGroup db adminsGroup
  case r1 of
    Left AlreadyExists -> return ()
    Left e -> error $ "Error creating admins group: " ++ show e
    Right _ -> return ()

  -- Create the admin user
  case decodeBase64 $ encodeUtf8 adminPublicKeyBase64 of
    Left _ -> error "Invalid base64 public key"
    Right adminPublicKey -> do
      uid <- UserUUID <$> nextRandom
      let pk = UserPublicKey (PublicKey adminPublicKey) "Admin public key"
      let user = User uid (Just adminEmail) [GroupId adminsGroupId] [] [pk]
      r2 <- runExceptT $ createUser db user
      case r2 of
        Left AlreadyExists -> return ()
        Left e -> error $ "Error creating admin: " ++ show e
        Right _ -> return ()
