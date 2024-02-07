{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

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
