{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Init (initDB) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString.Base64.URL
import Data.Text
import Data.Text.Encoding
import Data.UUID.V4

import IAM.Client (setSessionToken)
import IAM.Client.Auth
import IAM.Error
import IAM.Group
import IAM.GroupIdentifier
import IAM.Policy
import IAM.Server.DB
import IAM.Session
import IAM.User
import IAM.UserIdentifier
import IAM.UserPublicKey
import qualified IAM.Client as C


initDB :: DB db => Text -> Text -> Text -> Text -> db -> C.IAMClient -> IO SessionId
initDB iamHost eventsHost adminEmail adminPublicKeyBase64 db iamClient = do
  createAdmin iamHost adminEmail adminPublicKeyBase64 db
  createSystemUser eventsHost db iamClient


createAdmin :: DB db => Text -> Text -> Text -> db -> IO ()
createAdmin iamHost adminEmail adminPublicKeyBase64 db = do
  adminPolicyId <- PolicyUUID <$> nextRandom

  -- Create the admin policy
  let name = "iam-admin"
      allowReads = Rule Allow Read "**"
      allowWrites = Rule Allow Write "**"
      adminPolicy = Policy adminPolicyId (Just name) iamHost [allowReads, allowWrites]
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
      let mName = Just "admin"
          mEmail = Just adminEmail
          pk = UserPublicKey (PublicKey adminPublicKey) "Admin public key"
          user = User uid mName mEmail [GroupId adminsGroupId] [] [pk]
      r2 <- runExceptT $ createUser db user
      case r2 of
        Left AlreadyExists -> return ()
        Left e -> error $ "Error creating admin: " ++ show e
        Right _ -> return ()


createSystemUser :: DB db => Text -> db -> C.IAMClient -> IO SessionId
createSystemUser eventsHost db iamClient = do
  -- Check if the system policy exists
  r0 <- runExceptT $ getPolicy db $ PolicyName "iam-system"
  systemPolicyId <- case r0 of
    Left (NotFound _) -> PolicyUUID <$> nextRandom
    Left e -> error $ "Error getting system policy: " ++ show e
    Right policy -> return $ policyId policy

  -- Create the system policy
  let name = "iam-system"
      auditTopic = "f2d7835b-29f1-4f29-b3dd-04ce1d1ef939"
      writeAudit = Rule Allow Write $ "/topics/" <> auditTopic <> "/events/*"
      systemPolicy = Policy systemPolicyId (Just name) eventsHost [writeAudit]
  r1 <- runExceptT $ createPolicy db systemPolicy
  case r1 of
    Left AlreadyExists -> return ()
    Left e -> error $ "Error creating system policy: " ++ show e
    Right _ -> return ()

  -- Create the system user
  let iamConfig = C.iamClientConfig iamClient
  let systemPublicKeyBase64 = encodePublicKey $ C.iamClientConfigSecretKey iamConfig
  let systemUserIdentifier = C.iamClientConfigUserIdentifier iamConfig
  uid <- case decodeBase64 $ encodeUtf8 systemPublicKeyBase64 of
    Left _ -> error "Invalid base64 public key"
    Right systemPublicKey -> do
      uid <- case unUserIdentifierId systemUserIdentifier of
        Nothing -> UserUUID <$> nextRandom
        Just uid -> return uid
      let mName = Just "iam-system"
          mEmail = unUserIdentifierEmail systemUserIdentifier
          pk = UserPublicKey (PublicKey systemPublicKey) "System public key"
          user = User uid mName mEmail [] [PolicyId systemPolicyId] [pk]
      r2 <- runExceptT $ createUser db user
      case r2 of
        Left AlreadyExists -> return uid
        Left e -> error $ "Error creating system user: " ++ show e
        Right _ -> return uid

  -- Create a session for the system user
  r3 <- runExceptT $ IAM.Server.DB.createSession db (read "127.0.0.1") uid
  case r3 of
    Left e -> error $ "Error creating system session: " ++ show e
    Right sid -> do
      setSessionToken iamClient $ Just $ createSessionToken sid
      return $ createSessionId sid
