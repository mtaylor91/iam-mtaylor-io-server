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
      result <- liftIO $ runExceptT $ createUser db userPrincipal
      liftIO $ result `shouldBe` Right userPrincipal
      let headers =
            [ ("X-User-Id", "test@example.com")
            , ("X-Public-Key", encodeUtf8 $ encodeBase64 $ unPublicKey pk)
            , ("Authorization", "Signature " <> sig)
            ]
          sig = encodeUtf8 $ encodeBase64 $ unSignature $ dsign sk stringToSign
          stringToSign = authStringToSign methodGet "/users" ""
      request methodGet "/users" headers mempty `shouldRespondWith` 200
  describe "POST /users with email address" $ do
    it "responds with 201" $ do
      (pk, _) <- liftIO createKeypair
      let headers = [("Content-Type", "application/json")]
          uid = UserEmail "bob@example.com"
          user = UserPrincipal uid pk
          userJSON = encode user
      request methodPost "/users" headers userJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deleteUser db uid
      liftIO $ r `shouldBe` Right uid
  describe "POST /users with UUID" $ do
    it "responds with 201" $ do
      uuid <- liftIO nextRandom
      (pk, _) <- liftIO createKeypair
      let headers = [("Content-Type", "application/json")]
          user = UserPrincipal (UserUUID uuid) pk
          userJSON = encode user
      request methodPost "/users" headers userJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deleteUser db $ UserUUID uuid
      liftIO $ r `shouldBe` Right (UserUUID uuid)
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
