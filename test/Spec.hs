{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Network.HTTP.Types

import Test.Hspec
import Test.Hspec.Wai

import Lib (app)
import Lib.DB
import Lib.InMemory

main :: IO ()
main = do
  db <- inMemory
  hspec $ spec db

spec :: DB db => db -> Spec
spec db = with (return $ app db) $ do
  describe "GET /users" $ do
    it "responds with 200" $ do
      get "/users" `shouldRespondWith` 200
  describe "GET /groups" $ do
    it "responds with 200" $ do
      get "/groups" `shouldRespondWith` 200
  describe "POST /users" $ do
    it "responds with 201" $ do
      let headers = [("Content-Type", "application/json")]
      let userIdJSON = "{\"email\": \"bob@example.com\"}"
      request methodPost "/users" headers userIdJSON `shouldRespondWith` 201
  describe "POST /groups" $ do
    it "responds with 201" $ do
      let headers = [("Content-Type", "application/json")]
      let groupIdJSON = "{\"name\": \"admins\"}"
      request methodPost "/groups" headers groupIdJSON `shouldRespondWith` 201
