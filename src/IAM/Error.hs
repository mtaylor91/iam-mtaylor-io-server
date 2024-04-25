{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module IAM.Error ( module IAM.Error ) where

import Control.Monad.Except
import Data.Aeson
import Data.Text
import Servant

import IAM.Identifier


data Error
  = AuthenticationFailed AuthenticationError
  | NotAuthorized
  | AlreadyExists
  | NotFound Identifier
  | InternalError Text
  | ValidationError Text
  | NotImplemented
  deriving (Show, Eq)

instance ToJSON Error where
  toJSON (AuthenticationFailed e) = object
    [ "error" .= ("Authentication failed" :: Text)
    , "message" .= toJSON e
    ]
  toJSON NotAuthorized = object
    [ "error" .= ("Not Authorized" :: Text) ]
  toJSON AlreadyExists = object
    ["error" .= ("Already exists" :: Text)]
  toJSON (NotFound e) = object
    [ "error" .= ("Not found" :: Text)
    , "identifier" .= toJSON e
    ]
  toJSON (InternalError _) = object
    [ "error" .= ("Internal error" :: Text) ]
  toJSON NotImplemented = object
    [ "error" .= ("Not implemented" :: Text) ]
  toJSON (ValidationError e) = object
    [ "error" .= ("Validation error" :: Text)
    , "message" .= e
    ]


data AuthenticationError
  = AuthenticationRequired
  | InvalidHost
  | InvalidSignature
  | SessionRequired
  | SessionNotFound
  | UserNotFound
  deriving (Show, Eq)

instance ToJSON AuthenticationError where
  toJSON AuthenticationRequired = String "Authentication required"
  toJSON InvalidHost = String "Invalid Host"
  toJSON InvalidSignature = String "Invalid Signature"
  toJSON SessionRequired = String "Session authentication required"
  toJSON SessionNotFound = String "Session not found"
  toJSON UserNotFound = String "User not found"


errorHandler :: (MonadIO m, MonadError ServerError m) => Error -> m a
errorHandler err = do
  case err of
    (InternalError e) -> liftIO $ print e
    NotImplemented -> liftIO $ print err
    _             -> return ()
  throwError $ toServerError err


toServerError :: Error -> ServerError
toServerError e@(AuthenticationFailed _)  = augmentError e err401
toServerError e@NotAuthorized             = augmentError e err403
toServerError e@(NotFound _)              = augmentError e err404
toServerError e@AlreadyExists             = augmentError e err409
toServerError e@(InternalError _)         = augmentError e err500
toServerError e@NotImplemented            = augmentError e err501
toServerError e@(ValidationError _)       = augmentError e err400


augmentError :: Error -> ServerError -> ServerError
augmentError e err = err
  { errBody = encode e, errHeaders = [("Content-Type", "application/json")] }
