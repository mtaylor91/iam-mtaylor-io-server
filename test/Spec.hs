{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.Aeson
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding
import Data.Textual hiding (toString)
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Types

import Test.Hspec
import Test.Hspec.Wai

import IAM.Group
import IAM.GroupIdentifier
import IAM.Ip
import IAM.Policy
import IAM.Server.App (app)
import IAM.Server.Auth (stringToSign)
import IAM.Server.Context
import IAM.Server.DB
import IAM.Server.DB.InMemory
import IAM.Session hiding (createSession)
import IAM.User
import IAM.UserIdentifier


main :: IO ()
main = do
  db <- inMemory
  (pk, sk) <- createKeypair
  callerId <- UserUUID <$> nextRandom
  callerPolicyId <- PolicyUUID <$> nextRandom
  let allowReads = Rule Allow Read "**"
      allowWrites = Rule Allow Write "**"
      callerName = Just "testuser"
      callerEmail = Just "caller@example.com"
      callerPolicy = Policy callerPolicyId Nothing "localhost" callerPolicyRules
      callerPolicyRules = [allowReads, allowWrites]
      callerPrincipal = User callerId callerName callerEmail [] [] [UserPublicKey pk "test"]
  result0 <- runExceptT $ createUser db callerPrincipal
  case result0 of
    Right _  -> do
      result1 <- runExceptT $ createPolicy db callerPolicy
      case result1 of
        Right _ -> do
          let cid = UserIdentifier (Just callerId) Nothing Nothing
          let pid = PolicyId callerPolicyId
          result2 <- runExceptT $ createUserPolicyAttachment db cid pid
          case result2 of
            Right _ ->
              case maybeParsed $ parseText "127.0.0.1/32" of
                Just addr -> do
                  result3 <- runExceptT $ createSession db (IpAddr addr) callerId
                  case result3 of
                    Right callerSession ->
                      hspec $ spec "localhost" db pk sk callerSession
                    Left _ -> error "Failed to create test session"
                Nothing -> error "Failed to parse test IP address"
            Left _ -> error "Failed to attach test user policy"
        Left _ -> error "Failed to create test user policy"
    Left _ -> error "Failed to create test user"


spec :: DB db => Text -> db -> PublicKey -> SecretKey -> CreateSession -> Spec
spec host db callerPK callerSK callerSession = with (return $ app host $ Ctx db) $ do
  describe "GET /users" $ do
    it "responds with 200" $ do
      requestId <- liftIO nextRandom
      let headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 $ pack $ toString requestId)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodGet (encodeUtf8 host) "/users" "" requestId $
              Just $ createSessionToken callerSession
      request methodGet "/users" headers mempty `shouldRespondWith` 200
  describe "POST /users with email address" $ do
    it "responds with 201" $ do
      uid <- UserUUID <$> liftIO nextRandom
      (pk, _) <- liftIO createKeypair
      requestId <- liftIO nextRandom
      let user = User uid Nothing Nothing [] [] [UserPublicKey pk "test"]
          userJSON = encode user
          headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("Content-Type", "application/json")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 $ pack $ toString requestId)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodPost (encodeUtf8 host) "/users" "" requestId $
              Just $ createSessionToken callerSession
      request methodPost "/users" headers userJSON `shouldRespondWith` 201
      result <- liftIO $ runExceptT $ deleteUser db $ UserIdentifier (Just uid) Nothing Nothing
      liftIO $ result `shouldBe` Right user
  describe "POST /users with UUID" $ do
    it "responds with 201" $ do
      uuid <- liftIO nextRandom
      (pk, _) <- liftIO createKeypair
      requestId <- liftIO nextRandom
      let user = User (UserUUID uuid) Nothing Nothing [] [] [UserPublicKey pk "test"]
          userJSON = encode user
          headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("Content-Type", "application/json")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 $ pack $ toString requestId)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodPost (encodeUtf8 host) "/users" "" requestId $
              Just $ createSessionToken callerSession
      request methodPost "/users" headers userJSON `shouldRespondWith` 201
      result <- liftIO $ runExceptT $ deleteUser db $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing
      liftIO $ result `shouldBe` Right user
  describe "GET /groups" $ do
    it "responds with 200" $ do
      requestId <- liftIO nextRandom
      let headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 $ pack $ toString requestId)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodGet (encodeUtf8 host) "/groups" "" requestId $
              Just $ createSessionToken callerSession
      request methodGet "/groups" headers mempty `shouldRespondWith` 200
  describe "POST /groups" $ do
    it "responds with 201" $ do
      gid <- GroupUUID <$> liftIO nextRandom
      requestId <- liftIO nextRandom
      let headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("Content-Type", "application/json")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 $ pack $ toString requestId)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          group' = Group gid (Just "admins") [] []
          groupJSON = encode group'
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodPost (encodeUtf8 host) "/groups" "" requestId $
              Just $ createSessionToken callerSession
      request methodPost "/groups" headers groupJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deleteGroup db $ GroupName "admins"
      liftIO $ r `shouldBe` Right group'
  describe "GET /policies" $ do
    it "responds with 200" $ do
      requestId <- liftIO nextRandom
      let headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 requestIdString)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          requestIdString = pack $ toString requestId
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodGet (encodeUtf8 host) "/policies" "" requestId $
              Just $ createSessionToken callerSession
      request methodGet "/policies" headers mempty `shouldRespondWith` 200
  describe "POST /policies" $ do
    it "responds with 201" $ do
      pid <- PolicyUUID <$> liftIO nextRandom
      requestId <- liftIO nextRandom
      let headers =
            [ ("Authorization", "Signature " <> sig)
            , ("Host", "localhost")
            , ("Content-Type", "application/json")
            , ("X-MTaylor-IO-User-Id", "caller@example.com")
            , ("X-MTaylor-IO-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("X-MTaylor-IO-Request-Id", encodeUtf8 $ pack $ toString requestId)
            , ("X-MTaylor-IO-Session-Token", encodeUtf8 $ createSessionToken callerSession)
            ]
          policy = Policy pid Nothing "localhost" [Rule Allow Read "*", Rule Allow Write "*"]
          policyJSON = encode policy
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK authStringToSign
          authStringToSign =
            stringToSign methodPost (encodeUtf8 host) "/policies" "" requestId $
              Just $ createSessionToken callerSession
      request methodPost "/policies" headers policyJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deletePolicy db $ PolicyId pid
      liftIO $ r `shouldBe` Right policy
