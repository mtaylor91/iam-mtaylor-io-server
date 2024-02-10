{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.Aeson
import Data.ByteString.Base64
import Data.Text.Encoding
import Data.UUID.V4
import Network.HTTP.Types

import Test.Hspec
import Test.Hspec.Wai

import Lib (app)
import Lib.Auth (authStringToSign)
import Lib.IAM
import Lib.IAM.DB
import Lib.IAM.DB.InMemory

main :: IO ()
main = do
  db <- inMemory
  hspec $ spec db

spec :: DB db => db -> Spec
spec db = with (return $ app db) $ do
  describe "GET /users" $ do
    it "responds with 200" $ do
      (pk, sk) <- liftIO createKeypair
      let userPrincipal = UserPrincipal (UserEmail "test@example.com") pk
      r1 <- liftIO $ runExceptT $ createUser db userPrincipal
      liftIO $ r1 `shouldBe` Right userPrincipal
      let headers =
            [ ("X-User-Id", "test@example.com")
            , ("X-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey pk)
            , ("Authorization", "Signature " <> sig)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign sk stringToSign
          stringToSign = authStringToSign methodGet "/users" ""
      request methodGet "/users" headers mempty `shouldRespondWith` 200
      r2 <- liftIO $ runExceptT $ deleteUser db $ UserEmail "test@example.com"
      liftIO $ r2 `shouldBe` Right (UserEmail "test@example.com")
  describe "POST /users with email address" $ do
    it "responds with 201" $ do
      (pk, _) <- liftIO createKeypair
      (callerPK, callerSK) <- liftIO createKeypair
      let callerId = UserEmail "caller@example.com"
          callerPrincipal = UserPrincipal callerId callerPK
          uid = UserEmail "bob@example.com"
          user = UserPrincipal uid pk
          userJSON = encode user
          headers =
            [ ("Content-Type", "application/json")
            , ("X-User-Id", "caller@example.com")
            , ("X-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("Authorization", "Signature " <> sig)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK stringToSign
          stringToSign = authStringToSign methodPost "/users" ""
      r1 <- liftIO $ runExceptT $ createUser db callerPrincipal
      liftIO $ r1 `shouldBe` Right callerPrincipal
      request methodPost "/users" headers userJSON `shouldRespondWith` 201
      r2 <- liftIO $ runExceptT $ deleteUser db uid
      liftIO $ r2 `shouldBe` Right uid
      r3 <- liftIO $ runExceptT $ deleteUser db callerId
      liftIO $ r3 `shouldBe` Right callerId
  describe "POST /users with UUID" $ do
    it "responds with 201" $ do
      uuid <- liftIO nextRandom
      (pk, _) <- liftIO createKeypair
      (callerPK, callerSK) <- liftIO createKeypair
      let callerId = UserEmail "caller@example.com"
          callerPrincipal = UserPrincipal callerId callerPK
          user = UserPrincipal (UserUUID uuid) pk
          userJSON = encode user
          headers =
            [ ("Content-Type", "application/json")
            , ("X-User-Id", "caller@example.com")
            , ("X-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey callerPK)
            , ("Authorization", "Signature " <> sig)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign callerSK stringToSign
          stringToSign = authStringToSign methodPost "/users" ""
      r1 <- liftIO $ runExceptT $ createUser db callerPrincipal
      liftIO $ r1 `shouldBe` Right callerPrincipal
      request methodPost "/users" headers userJSON `shouldRespondWith` 201
      r2 <- liftIO $ runExceptT $ deleteUser db $ UserUUID uuid
      liftIO $ r2 `shouldBe` Right (UserUUID uuid)
      r3 <- liftIO $ runExceptT $ deleteUser db callerId
      liftIO $ r3 `shouldBe` Right callerId
  describe "GET /groups" $ do
    it "responds with 200" $ do
      get "/groups" `shouldRespondWith` 200
  describe "POST /groups" $ do
    it "responds with 201" $ do
      let headers = [("Content-Type", "application/json")]
          group = Group (GroupName "admins") []
          groupJSON = encode group
      request methodPost "/groups" headers groupJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deleteGroup db $ GroupName "admins"
      liftIO $ r `shouldBe` Right ()
  describe "GET /policies" $ do
    it "responds with 200" $ do
      get "/policies" `shouldRespondWith` 200
  describe "POST /policies" $ do
    it "responds with 201" $ do
      pid <- liftIO nextRandom
      let headers = [("Content-Type", "application/json")]
          policy = Policy pid [Rule Allow Read "*", Rule Allow Write "*"]
          policyJSON = encode policy
      request methodPost "/policies" headers policyJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deletePolicy db pid
      liftIO $ r `shouldBe` Right policy
