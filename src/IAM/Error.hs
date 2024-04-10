{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
module IAM.Error ( module IAM.Error ) where

import Control.Monad.Except
import Data.ByteString.Lazy (fromStrict)
import Data.Text
import Data.Text.Encoding
import Servant


data Error
  = AlreadyExists
  | NotFound Text Text
  | InternalError Text
  | NotImplemented
  deriving (Show, Eq)


errorHandler :: (MonadIO m, MonadError ServerError m) => Error -> m a
errorHandler err = do
  case err of
    (InternalError e) -> liftIO $ print e
    NotImplemented -> liftIO $ print err
    _             -> return ()
  throwError $ toServerError err


toServerError :: Error -> ServerError
toServerError AlreadyExists     = err409
toServerError NotImplemented    = err501
toServerError (InternalError _) = err500
toServerError (NotFound r n)    = err404
  { errBody = t r <> " " <> t n <> " not found" }
  where t = fromStrict . encodeUtf8
