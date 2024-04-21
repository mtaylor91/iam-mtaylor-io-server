module IAM.Server.App
  ( app
  , startApp
  ) where

import Data.Text
import Network.Wai.Handler.Warp
import Network.Wai.Middleware.RequestLogger
import Servant

import IAM.API
import IAM.Server.API
import IAM.Server.Auth
import IAM.Server.Context
import IAM.Server.DB


app :: DB db => Text -> Ctx db -> Application
app host ctx = serveWithContext api (authContext host ctx) $ server ctx


startApp :: DB db => Int -> Text -> Ctx db -> IO ()
startApp port host ctx = do
  logger <- mkRequestLogger $ defaultRequestLoggerSettings
    { outputFormat = Apache FromFallback }
  run port $ logger $ app host ctx
