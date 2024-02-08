module Lib.Server ( app, startApp ) where

import Network.Wai
import Network.Wai.Handler.Warp
import Servant

import Lib.API
import Lib.DB

startApp :: DB db => db -> Int -> IO ()
startApp db port = run port $ app db

app :: DB db => db -> Application
app db = serve api $ server db

server :: DB db => db -> Server API
server db = usersAPI db :<|> groupsAPI db :<|> membershipsAPI db
