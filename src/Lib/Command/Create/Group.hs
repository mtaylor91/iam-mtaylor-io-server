module Lib.Command.Create.Group
  ( createGroup
  , createGroupOptions
  , CreateGroup(..)
  ) where

import Control.Exception
import Data.Text
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import Lib.Client.Auth
import Lib.Client.Util
import Lib.IAM (Group(..), GroupId(..), UserId(..))
import qualified Lib.Client


data CreateGroup = CreateGroup
  { createGroupId :: !Text
  , createGroupPolicies :: ![Text]
  , createGroupUsers :: ![Text]
  } deriving (Show)


createGroup :: CreateGroup -> IO ()
createGroup createGroupInfo =
  case readMaybe (unpack $ createGroupId createGroupInfo) of
    Just uuid -> createGroupByUUID createGroupInfo uuid
    Nothing -> createGroupByName createGroupInfo $ createGroupId createGroupInfo


createGroupByName :: CreateGroup -> Text -> IO ()
createGroupByName createGroupInfo = createGroupById createGroupInfo . GroupName


createGroupByUUID :: CreateGroup -> UUID -> IO ()
createGroupByUUID createGroupInfo = createGroupById createGroupInfo . GroupUUID


createGroupById :: CreateGroup -> GroupId -> IO ()
createGroupById createGroupInfo gid = do
  policies <- mapM translatePolicyId $ createGroupPolicies createGroupInfo
  users <- mapM translateUserId $ createGroupUsers createGroupInfo
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  let grp = Group gid users policies
  res <- runClientM (Lib.Client.createGroup grp) $ mkClientEnv mgr url
  case res of
    Left err -> handleClientError err
    Right _ -> return ()

  where

    translatePolicyId :: Text -> IO UUID
    translatePolicyId pid = do
      case readMaybe (unpack pid) of
        Just uuid -> return uuid
        Nothing -> throw $ userError $ "Invalid policy ID: " ++ show pid

    translateUserId :: Text -> IO UserId
    translateUserId uid = do
      case readMaybe (unpack uid) of
        Just uuid -> return $ UserUUID uuid
        Nothing -> return $ UserEmail uid


createGroupOptions :: Parser CreateGroup
createGroupOptions = CreateGroup
  <$> argument str
    (  metavar "GROUP"
    <> help "The name or uuid of the group to create"
    )
  <*> many (strOption
    ( long "policy"
    <> short 'p'
    <> metavar "POLICY"
    <> help "The ID of a policy to attach to the group"
    ))
  <*> many (strOption
    ( long "user"
    <> short 'u'
    <> metavar "USER"
    <> help "The ID of a user to add to the group"
    ))
