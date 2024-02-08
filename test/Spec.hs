{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.Aeson
import Data.UUID.V4
import Network.HTTP.Types

import Test.Hspec
import Test.Hspec.Wai

import Lib (app)
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
      get "/users" `shouldRespondWith` 200
  describe "POST /users" $ do
    it "responds with 201" $ do
      let headers = [("Content-Type", "application/json")]
      let userIdJSON = "{\"email\": \"bob@example.com\"}"
      request methodPost "/users" headers userIdJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deleteUser db $ UserEmailId "bob@example.com"
      liftIO $ r `shouldBe` Right ()
  describe "GET /groups" $ do
    it "responds with 200" $ do
      get "/groups" `shouldRespondWith` 200
  describe "POST /groups" $ do
    it "responds with 201" $ do
      let headers = [("Content-Type", "application/json")]
      let groupIdJSON = "{\"name\": \"admins\"}"
      request methodPost "/groups" headers groupIdJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deleteGroup db $ GroupNameId "admins"
      liftIO $ r `shouldBe` Right ()
  describe "GET /policies" $ do
    it "responds with 200" $ do
      get "/policies" `shouldRespondWith` 200
  describe "POST /policies" $ do
    it "responds with 201" $ do
      pid <- liftIO $ nextRandom
      let headers = [("Content-Type", "application/json")]
      let allowRead = PolicyRule Allow Read "*"
          allowWrite = PolicyRule Allow Write "*"
          policy = Policy pid [allowRead, allowWrite]
          policyJSON = encode policy
      request methodPost "/policies" headers policyJSON `shouldRespondWith` 201
      r <- liftIO $ runExceptT $ deletePolicy db pid
      liftIO $ r `shouldBe` Right policy
